package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	proxymanConfig "github.com/xtls/xray-core/app/proxyman"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/proxy/vless/l3client"
	"github.com/xtls/xray-core/proxy/vless/virtualnet"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre  uint32
	initpre  sync.Once
	preConns chan *ConnExpire

	// l3 holds state for the optional virtualNetwork L3-tunnel mode.
	// Nil means virtualNetwork is disabled and this outbound behaves as
	// a standard VLESS proxy; non-nil means every Process() call is
	// repurposed into an L3 tunnel session. See runL3Bootstrap and the
	// virtualnet/ package for the protocol.
	l3 *l3State
}

// l3State groups the fields only used by virtualNetwork mode so the
// default (nil) zero value keeps the Handler's hot path free of extra
// branches. Populated in New() only if config.VirtualNetwork.Enabled.
type l3State struct {
	client    *l3client.Client
	subnet    netip.Prefix
	bootCtx   context.Context
	cancelBoot context.CancelFunc
	done      chan struct{}
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		rvsCtx := session.ContextWithInbound(ctx, &session.Inbound{
			Tag:  a.Reverse.Tag,
			Name: "vless-reverse",
			User: handler.server.User, // TODO: email
		})
		if sc := a.Reverse.Sniffing; sc != nil && sc.Enabled {
			request, err := proxymanConfig.BuildSniffingRequest(sc)
			if err != nil {
				return nil, errors.New("failed to build reverse sniffing request").Base(err).AtError()
			}
			rvsCtx = session.ContextWithContent(rvsCtx, &session.Content{
				SniffingRequest: request,
			})
		}
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx:        rvsCtx,
			handler:    handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		go func() {
			time.Sleep(2 * time.Second)
			handler.reverse.Start()
		}()
	}

	handler.testpre = a.Testpre

	if vn := config.VirtualNetwork; vn != nil && vn.Enabled {
		subnetStr := vn.Subnet
		if subnetStr == "" {
			subnetStr = "10.0.0.0/24"
		}
		subnet, err := netip.ParsePrefix(subnetStr)
		if err != nil {
			return nil, errors.New("invalid virtualNetwork.subnet: " + subnetStr).Base(err)
		}
		cli, err := l3client.NewClient(l3client.Config{
			Subnet:        subnet,
			InterfaceName: vn.InterfaceName,
			MTU:           int(vn.Mtu),
			DefaultRoute:  vn.DefaultRoute,
		})
		if err != nil {
			return nil, errors.New("virtualNetwork client").Base(err)
		}
		// ctx here already carries session.FullHandler (set by
		// proxyman/outbound.NewHandler). We capture it for
		// runL3Bootstrap which needs to synthesise per-attempt
		// contexts that reference the same outer proxyman handler.
		bootCtx, cancelBoot := context.WithCancel(ctx)
		handler.l3 = &l3State{
			client:     cli,
			subnet:     subnet,
			bootCtx:    bootCtx,
			cancelBoot: cancelBoot,
			done:       make(chan struct{}),
		}
		go handler.runL3Bootstrap()
	}

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.preConns != nil {
		close(h.preConns)
	}
	if h.l3 != nil {
		h.l3.cancelBoot()
		<-h.l3.done
	}
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	if h.testpre > 0 && h.reverse == nil {
		h.initpre.Do(func() {
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				go func() {
					defer func() { recover() }()
					ctx := xctx.ContextWithID(context.Background(), session.NewID())
					for {
						conn, err := dialer.Dial(ctx, rec.Destination)
						if err != nil {
							errors.LogWarningInner(ctx, err, "pre-connect failed")
							continue
						}
						h.preConns <- &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)} // TODO: customize & randomize
						time.Sleep(time.Millisecond * 200)                                             // TODO: customize & randomize
					}
				}()
			}
		})
		for {
			connTime := <-h.preConns
			if connTime == nil {
				return errors.New("closed handler").AtWarning()
			}
			if time.Now().Before(connTime.Expire) {
				conn = connTime.Conn
				break
			}
			connTime.Conn.Close()
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	ob.Conn = conn // for Vision's pre-connect

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var t reflect.Type
			var p uintptr
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = uintptr(unsafe.Pointer(commonConn))
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
		default:
			panic("unknown VLESS request command")
		}
	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	// virtualNetwork mode: after the standard VLESS handshake, hand the
	// post-handshake byte stream to the L3 client, which reads the
	// assigned-IP preamble and runs the TUN<->stream packet loop. This
	// branch bypasses the normal body-copy task.Run entirely; the
	// link passed in by runL3Bootstrap is not used past this point.
	if h.l3 != nil {
		return h.processL3(ctx, conn, request, requestAddons, trafficState, ob, timer)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range r.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	if len(activeWorkers) != len(r.workers) {
		r.workers = activeWorkers
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range r.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.workers = append(r.workers, w)
		go func() {
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
	}
	return nil
}

func (r *Reverse) Start() error {
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	return r.monitorTask.Close()
}

// processL3 handles the virtualNetwork body path: encodes the VLESS
// request header onto conn, decodes the response header, wraps the
// post-handshake byte stream as an io.ReadWriteCloser, and runs the
// l3client packet loop. It returns when the tunnel ends.
//
// The activity timer created by the caller is passed into the client
// so each TUN read and stream read feeds Update(), preventing the
// connection-idle cancel from firing on a busy tunnel.
func (h *Handler) processL3(
	ctx context.Context,
	conn stat.Connection,
	request *protocol.RequestHeader,
	requestAddons *encoding.Addons,
	trafficState *proxy.TrafficState,
	ob *session.Outbound,
	timer *signal.ActivityTimer,
) error {
	if request.Command != protocol.RequestCommandTCP || requestAddons.Flow != "" {
		return errors.New("virtualNetwork: only flow=\"\" and command=TCP are supported")
	}

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
	if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
		return errors.New("virtualNetwork: encode request header").Base(err).AtWarning()
	}
	// Flush the header onto the wire so the server can transition out
	// of its header-reading state before we begin bidirectional I/O.
	if err := bufferWriter.SetBuffered(false); err != nil {
		return errors.New("virtualNetwork: flush request header").Base(err).AtWarning()
	}

	if _, err := encoding.DecodeResponseHeader(conn, request); err != nil {
		return errors.New("virtualNetwork: decode response header").Base(err).AtInfo()
	}

	// Disable the inactivity-kill: the l3 client feeds Update() on
	// every packet, so as long as the tunnel is carrying traffic the
	// timer will not fire. This avoids reusing a tiny ConnectionIdle
	// timeout (which is sized for a web-proxy request/response, not a
	// long-lived VPN).
	timer.SetTimeout(time.Hour * 24 * 365)

	serverReader := buf.NewReader(conn)
	serverWriter := buf.NewWriter(conn)
	stream := virtualnet.NewStreamConn(serverReader, serverWriter, conn)
	_ = trafficState
	_ = ob

	// Extract the resolved server IP from the established conn so the
	// device layer can install a /32 host-route exclusion before any
	// default-route hijack. Domain names in vnext are resolved by the
	// standard outbound dialer, so RemoteAddr is the actual IP we need.
	var serverIP netip.Addr
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			serverIP = a.Unmap()
		}
	}

	return h.l3.client.Run(ctx, stream, timer, serverIP)
}

// runL3Bootstrap is the keeper goroutine for virtualNetwork mode. It
// loops forever (until the handler is closed) dispatching into the
// handler's own Process() via a synthetic link and a sentinel target.
// On error it backs off with capped exponential delay.
func (h *Handler) runL3Bootstrap() {
	defer close(h.l3.done)

	// Wait a short beat so the rest of core has finished initialising
	// (outbound manager, dns, routing) before we try to dial. Mirrors
	// the reverse-proxy bootstrap delay.
	select {
	case <-h.l3.bootCtx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	backoff := time.Second
	for {
		if err := h.l3.bootCtx.Err(); err != nil {
			return
		}
		started := time.Now()
		err := h.l3Dial(h.l3.bootCtx)
		if h.l3.bootCtx.Err() != nil {
			return
		}
		if err != nil {
			errors.LogWarningInner(h.l3.bootCtx, err, "virtualNetwork bootstrap attempt failed")
		}
		// If the tunnel stayed up for at least 30 seconds, reset the
		// backoff; otherwise double it up to a minute.
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		} else {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
		select {
		case <-h.l3.bootCtx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// l3Dial performs a single virtualNetwork connection attempt. It wires
// up a synthetic transport.Link (unused by processL3) and dispatches
// through the handler's own Process so all the normal stream settings
// (TLS/REALITY/transport) are applied by the outer proxyman handler.
func (h *Handler) l3Dial(bootCtx context.Context) error {
	fullHandler := session.FullHandlerFromContext(bootCtx)
	if fullHandler == nil {
		return errors.New("virtualNetwork: no FullHandler on bootstrap ctx")
	}
	pmHandler, ok := fullHandler.(internet.Dialer)
	if !ok {
		return errors.New("virtualNetwork: FullHandler does not implement internet.Dialer")
	}

	// Synthesise the outbound target. The server-side inbound ignores
	// the target when its virtualNetwork is enabled, so any routable
	// address works; we use the subnet gateway to make traces readable.
	gateway := h.l3.subnet.Masked().Addr().Next()
	outCtx := session.ContextWithOutbounds(bootCtx, []*session.Outbound{{
		Target: net.Destination{
			Network: net.Network_TCP,
			Address: net.IPAddress(gateway.AsSlice()),
			Port:    net.Port(1),
		},
	}})
	outCtx = xctx.ContextWithID(outCtx, session.NewID())

	reader, writer := pipe.New(pipe.WithSizeLimit(buf.Size))
	link := &transport.Link{Reader: reader, Writer: writer}
	defer common.Interrupt(reader)
	defer common.Close(writer)

	return h.Process(outCtx, link, pmHandler)
}
