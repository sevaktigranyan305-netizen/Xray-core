package inbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"io"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/extension"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/proxy/vless/virtualnet"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var dc dns.Client
		if err := core.RequireFeatures(ctx, func(d dns.Client) error {
			dc = d
			return nil
		}); err != nil {
			return nil, err
		}

		c := config.(*Config)

		validator := new(vless.MemoryValidator)
		for _, user := range c.Clients {
			u, err := user.ToMemoryUser()
			if err != nil {
				return nil, errors.New("failed to get VLESS user").Base(err).AtError()
			}
			if err := validator.Add(u); err != nil {
				return nil, errors.New("failed to initiate user").Base(err).AtError()
			}
		}

		return New(ctx, c, dc, validator)
	}))
}

// Handler is an inbound connection handler that handles messages in VLess protocol.
type Handler struct {
	inboundHandlerManager  feature_inbound.Manager
	policyManager          policy.Manager
	stats                  stats.Manager
	validator              vless.Validator
	decryption             *encryption.ServerInstance
	outboundHandlerManager outbound.Manager
	observer               features.Feature
	defaultDispatcher      routing.Dispatcher
	ctx                    context.Context
	fallbacks              map[string]map[string]map[string]*Fallback // or nil
	// regexps               map[string]*regexp.Regexp       // or nil

	// vnet is the optional virtual L3 network switch. It is non-nil
	// only when the inbound config sets virtualNetwork.enabled=true.
	// When nil all code paths behave exactly as vanilla VLESS.
	vnet *virtualnet.Switch

	// inboundTag holds this VLESS inbound's user-facing tag (e.g.
	// "inbound-443" emitted by 3x-ui). Captured on the first Process
	// call from session.InboundFromContext, then read by the
	// virtualnet ConnHandler so synthesised L3 sub-flows route as if
	// they originated from this inbound — without it, routing rules
	// keyed on inboundTag (or balancer rules referencing them) never
	// match for L3 traffic and silently fall through to the default
	// outbound. atomic.Pointer to make the read/write race-free.
	inboundTag atomic.Pointer[string]
}

// New creates a new VLess inbound handler.
func New(ctx context.Context, config *Config, dc dns.Client, validator vless.Validator) (*Handler, error) {
	v := core.MustFromContext(ctx)
	handler := &Handler{
		inboundHandlerManager:  v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		policyManager:          v.GetFeature(policy.ManagerType()).(policy.Manager),
		stats:                  v.GetFeature(stats.ManagerType()).(stats.Manager),
		validator:              validator,
		outboundHandlerManager: v.GetFeature(outbound.ManagerType()).(outbound.Manager),
		observer:               v.GetFeature(extension.ObservatoryType()),
		defaultDispatcher:      v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
		ctx:                    ctx,
	}

	if config.Decryption != "" && config.Decryption != "none" {
		s := strings.Split(config.Decryption, ".")
		var nfsSKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsSKeysBytes = append(nfsSKeysBytes, b)
		}
		handler.decryption = &encryption.ServerInstance{}
		if err := handler.decryption.Init(nfsSKeysBytes, config.XorMode, config.SecondsFrom, config.SecondsTo, config.Padding); err != nil {
			return nil, errors.New("failed to use decryption").Base(err).AtError()
		}
	}

	if config.Fallbacks != nil {
		handler.fallbacks = make(map[string]map[string]map[string]*Fallback)
		// handler.regexps = make(map[string]*regexp.Regexp)
		for _, fb := range config.Fallbacks {
			if handler.fallbacks[fb.Name] == nil {
				handler.fallbacks[fb.Name] = make(map[string]map[string]*Fallback)
			}
			if handler.fallbacks[fb.Name][fb.Alpn] == nil {
				handler.fallbacks[fb.Name][fb.Alpn] = make(map[string]*Fallback)
			}
			handler.fallbacks[fb.Name][fb.Alpn][fb.Path] = fb
			/*
				if fb.Path != "" {
					if r, err := regexp.Compile(fb.Path); err != nil {
						return nil, errors.New("invalid path regexp").Base(err).AtError()
					} else {
						handler.regexps[fb.Path] = r
					}
				}
			*/
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn := range handler.fallbacks[""] {
						if apfb[alpn] == nil {
							apfb[alpn] = make(map[string]*Fallback)
						}
					}
				}
			}
		}
		for _, apfb := range handler.fallbacks {
			if apfb[""] != nil {
				for alpn, pfb := range apfb {
					if alpn != "" { // && alpn != "h2" {
						for path, fb := range apfb[""] {
							if pfb[path] == nil {
								pfb[path] = fb
							}
						}
					}
				}
			}
		}
		if handler.fallbacks[""] != nil {
			for name, apfb := range handler.fallbacks {
				if name != "" {
					for alpn, pfb := range handler.fallbacks[""] {
						for path, fb := range pfb {
							if apfb[alpn][path] == nil {
								apfb[alpn][path] = fb
							}
						}
					}
				}
			}
		}
	}

	if vn := config.GetVirtualNetwork(); vn.GetEnabled() {
		if err := handler.initVirtualNetwork(vn); err != nil {
			return nil, errors.New("failed to init virtualNetwork").Base(err).AtError()
		}
	}

	return handler, nil
}

// initVirtualNetwork builds the handler's *virtualnet.Switch from its
// protobuf-level configuration. The switch owns its own gVisor userspace
// stack; TCP/UDP flows terminated by that stack are forwarded to
// handler.defaultDispatcher with the originating user's virtual IP as
// the inbound source so that xray routing rules can key on sourceIP.
func (h *Handler) initVirtualNetwork(cfg *VirtualNetwork) error {
	subnetStr := cfg.GetSubnet()
	if subnetStr == "" {
		// Default matches the task's example config.
		subnetStr = "10.0.0.0/24"
	}
	prefix, err := netip.ParsePrefix(subnetStr)
	if err != nil {
		return errors.New("invalid subnet " + subnetStr).Base(err)
	}

	sw, err := virtualnet.NewSwitch(h.ctx, virtualnet.Config{
		Subnet:         prefix,
		PersistMapping: cfg.GetPersistMapping(),
		Handler:        h.virtualNetworkConnHandler(),
	})
	if err != nil {
		return err
	}
	h.vnet = sw
	return nil
}

// virtualNetworkConnHandler builds the ConnHandler closure passed into
// virtualnet.Switch. It is invoked for every TCP/UDP flow that reaches
// the virtual gateway and needs to be forwarded out via xray.
//
// The flow's source IP (the originating user's virtual IP) becomes the
// xray session.Inbound.Source, which is what rules like
// {"sourceIP": "10.0.0.2"} match on.
func (h *Handler) virtualNetworkConnHandler() virtualnet.ConnHandler {
	return func(srcVirtIP netip.Addr, dst net.Destination, conn net.Conn) {
		if h.defaultDispatcher == nil {
			_ = conn.Close()
			return
		}
		ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(h.ctx))
		defer cancel()
		ctx = c.ContextWithID(ctx, session.NewID())

		inbound := &session.Inbound{
			Name:   "vless",
			Source: net.DestinationFromAddr(conn.RemoteAddr()),
		}
		// Propagate the original VLESS inbound's Tag onto the
		// synthesised sub-flow so user-defined routing rules that key
		// on inboundTag (e.g. {"inboundTag":["inbound-443"], ...}
		// emitted by 3x-ui) match for L3 traffic. Without this, every
		// L3 sub-flow surfaces with an empty tag and falls through to
		// the default outbound regardless of how the inbound is
		// referenced in routing rules or balancers.
		if tagPtr := h.inboundTag.Load(); tagPtr != nil {
			inbound.Tag = *tagPtr
		}
		// Overwrite Source with the user's virtual IP so that routing
		// rules referencing sourceIP match the virtual network
		// address instead of the underlying transport endpoint.
		inbound.Source = net.Destination{
			Network: dst.Network,
			Address: net.IPAddress(srcVirtIP.AsSlice()),
			Port:    0,
		}
		// If the IPAM knows which user owns this IP, attach the
		// MemoryUser so user-targeted rules (email, level) still work.
		if uuidStr, ok := h.vnet.IPAM().UUIDOf(srcVirtIP); ok {
			if parsed, perr := uuid.ParseString(uuidStr); perr == nil {
				if u := h.validator.Get(parsed); u != nil {
					inbound.User = u
				}
			}
		}
		ctx = session.ContextWithInbound(ctx, inbound)
		// Enable HTTP+TLS sniffing for virtualnet sub-flows so that
		// server-side routing rules that key on domain (including
		// geosite:*) match the same way they would for a classic
		// VLESS inbound with sniffing configured. We force RouteOnly
		// because:
		//   1. We already wrote the dispatch destination explicitly
		//      (potentially rewritten from gateway-IP to loopback
		//      below). If the sniffer was allowed to override the
		//      destination, an HTTP `Host: 10.0.0.1` header would
		//      yank Target back to 10.0.0.1, undoing the rewrite,
		//      and freedom would dial an unreachable address.
		//   2. For non-gateway flows, the L3 client already picked
		//      a real destination IP — re-dialing by sniffed domain
		//      would force a server-side DNS lookup that the user
		//      did not ask for. RouteOnly keeps domain-based routing
		//      working without surprising DNS behaviour.
		ctx = session.ContextWithContent(ctx, &session.Content{
			SniffingRequest: session.SniffingRequest{
				Enabled:                        true,
				OverrideDestinationForProtocol: []string{"http", "tls"},
				RouteOnly:                      true,
			},
		})

		// Gateway-IP rewrite: if the user addressed the virtual
		// gateway directly (e.g. `curl http://10.0.0.1:4747` to reach
		// a service that listens on 0.0.0.0 on the VPS host), the
		// gVisor stack accepted the TCP/UDP handshake on the gateway
		// address — but the dispatcher would otherwise hand 10.0.0.1
		// to the freedom outbound, which would then dial 10.0.0.1
		// over the host network where no real interface owns that IP
		// and the connection collapses with "empty reply from server".
		// Rewriting to 127.0.0.1 here makes the gateway IP semantically
		// equivalent to "the host running xray", which matches what
		// users coming from a WireGuard background expect.
		//
		// We also rename inbound.Name to "virtualnet-gateway" so that
		// freedom's defaultPrivateBlockIPMatcher doesn't refuse the
		// dial: that matcher is automatically applied for inbounds
		// whose Name is "vless" / "vmess" / "trojan" / "hysteria" /
		// "wireguard" / "shadowsocks*" (see proxy/freedom/freedom.go
		// getBlockedIPMatcher), and it considers 127.0.0.0/8 a
		// blocked private destination — which would otherwise close
		// the connection right after dial with the inbound observing
		// "empty reply from server". Hitting the host loopback is
		// exactly what the gateway-IP rewrite is meant to enable, so
		// stepping outside that policy here is intentional and the
		// scope is the one rewritten flow only.
		dispatchDst := dst
		if dispatchDst.Address.Family().IsIP() && h.vnet != nil {
			if hostIP, ok := netip.AddrFromSlice(dispatchDst.Address.IP()); ok {
				if hostIP.Unmap() == h.vnet.Gateway() {
					dispatchDst.Address = net.LocalHostIP
					inbound.Name = "virtualnet-gateway"
				}
			}
		}

		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   inbound.Source,
			To:     dispatchDst,
			Status: log.AccessAccepted,
			Reason: "virtualnet",
		})

		if err := h.defaultDispatcher.DispatchLink(ctx, dispatchDst, &transport.Link{
			Reader: buf.NewReader(conn),
			Writer: buf.NewWriter(conn),
		}); err != nil {
			errors.LogInfoInner(ctx, err, "virtualnet dispatch ends")
		}
		_ = conn.Close()
	}
}

func isMuxAndNotXUDP(request *protocol.RequestHeader, first *buf.Buffer) bool {
	if request.Command != protocol.RequestCommandMux {
		return false
	}
	if first.Len() < 7 {
		return true
	}
	firstBytes := first.Bytes()
	return !(firstBytes[2] == 0 && // ID high
		firstBytes[3] == 0 && // ID low
		firstBytes[6] == 2) // Network type: UDP
}

func (h *Handler) GetReverse(a *vless.MemoryAccount) (*Reverse, error) {
	u := h.validator.Get(a.ID.UUID())
	if u == nil {
		return nil, errors.New("reverse: user " + a.ID.String() + " doesn't exist anymore")
	}
	a = u.Account.(*vless.MemoryAccount)
	if a.Reverse == nil || a.Reverse.Tag == "" {
		return nil, errors.New("reverse: user " + a.ID.String() + " is not allowed to create reverse proxy")
	}
	r := h.outboundHandlerManager.GetHandler(a.Reverse.Tag)
	if r == nil {
		picker, _ := reverse.NewStaticMuxPicker()
		r = &Reverse{tag: a.Reverse.Tag, picker: picker, client: &mux.ClientManager{Picker: picker}}
		for len(h.outboundHandlerManager.ListHandlers(h.ctx)) == 0 {
			time.Sleep(time.Second) // prevents this outbound from becoming the default outbound
		}
		if err := h.outboundHandlerManager.AddHandler(h.ctx, r); err != nil {
			return nil, err
		}
	}
	if r, ok := r.(*Reverse); ok {
		return r, nil
	}
	return nil, errors.New("reverse: outbound " + a.Reverse.Tag + " is not type Reverse")
}

func (h *Handler) RemoveReverse(u *protocol.MemoryUser) {
	if u != nil {
		a := u.Account.(*vless.MemoryAccount)
		if a.Reverse != nil && a.Reverse.Tag != "" {
			h.outboundHandlerManager.RemoveHandler(h.ctx, a.Reverse.Tag)
		}
	}
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.decryption != nil {
		h.decryption.Close()
	}
	for _, u := range h.validator.GetAll() {
		h.RemoveReverse(u)
	}
	if h.vnet != nil {
		_ = h.vnet.Close()
	}
	return errors.Combine(common.Close(h.validator))
}

// AddUser implements proxy.UserManager.AddUser().
func (h *Handler) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return h.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (h *Handler) RemoveUser(ctx context.Context, e string) error {
	h.RemoveReverse(h.validator.GetByEmail(e))
	return h.validator.Del(e)
}

// GetUser implements proxy.UserManager.GetUser().
func (h *Handler) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return h.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.GetUsers().
func (h *Handler) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return h.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (h *Handler) GetUsersCount(context.Context) int64 {
	return h.validator.GetCount()
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatch routing.Dispatcher) error {
	iConn := stat.TryUnwrapStatsConn(connection)

	if h.decryption != nil {
		var err error
		if connection, err = h.decryption.Handshake(connection, nil); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	sessionPolicy := h.policyManager.ForLevel(0)
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return errors.New("unable to set read deadline").Base(err).AtWarning()
	}

	first := buf.FromBytes(make([]byte, buf.Size))
	first.Clear()
	firstLen, errR := first.ReadFrom(connection)
	if errR != nil {
		return errR
	}
	errors.LogInfo(ctx, "firstLen = ", firstLen)

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(connection),
		Buffer: buf.MultiBuffer{first},
	}

	var userSentID []byte // not MemoryAccount.ID
	var request *protocol.RequestHeader
	var requestAddons *encoding.Addons
	var err error

	napfb := h.fallbacks
	isfb := napfb != nil

	if isfb && firstLen < 18 {
		err = errors.New("fallback directly")
	} else {
		userSentID, request, requestAddons, isfb, err = encoding.DecodeRequestHeader(isfb, first, reader, h.validator)
	}

	if err != nil {
		if isfb {
			if err := connection.SetReadDeadline(time.Time{}); err != nil {
				errors.LogWarningInner(ctx, err, "unable to set back read deadline")
			}
			errors.LogInfoInner(ctx, err, "fallback starts")

			name := ""
			alpn := ""
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				cs := tlsConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				errors.LogInfo(ctx, "realName = "+name)
				errors.LogInfo(ctx, "realAlpn = "+alpn)
			} else if realityConn, ok := iConn.(*reality.Conn); ok {
				cs := realityConn.ConnectionState()
				name = cs.ServerName
				alpn = cs.NegotiatedProtocol
				errors.LogInfo(ctx, "realName = "+name)
				errors.LogInfo(ctx, "realAlpn = "+alpn)
			}
			name = strings.ToLower(name)
			alpn = strings.ToLower(alpn)

			if len(napfb) > 1 || napfb[""] == nil {
				if name != "" && napfb[name] == nil {
					match := ""
					for n := range napfb {
						if n != "" && strings.Contains(name, n) && len(n) > len(match) {
							match = n
						}
					}
					name = match
				}
			}

			if napfb[name] == nil {
				name = ""
			}
			apfb := napfb[name]
			if apfb == nil {
				return errors.New(`failed to find the default "name" config`).AtWarning()
			}

			if apfb[alpn] == nil {
				alpn = ""
			}
			pfb := apfb[alpn]
			if pfb == nil {
				return errors.New(`failed to find the default "alpn" config`).AtWarning()
			}

			path := ""
			if len(pfb) > 1 || pfb[""] == nil {
				/*
					if lines := bytes.Split(firstBytes, []byte{'\r', '\n'}); len(lines) > 1 {
						if s := bytes.Split(lines[0], []byte{' '}); len(s) == 3 {
							if len(s[0]) < 8 && len(s[1]) > 0 && len(s[2]) == 8 {
								errors.New("realPath = " + string(s[1])).AtInfo().WriteToLog(sid)
								for _, fb := range pfb {
									if fb.Path != "" && h.regexps[fb.Path].Match(s[1]) {
										path = fb.Path
										break
									}
								}
							}
						}
					}
				*/
				if firstLen >= 18 && first.Byte(4) != '*' { // not h2c
					firstBytes := first.Bytes()
					for i := 4; i <= 8; i++ { // 5 -> 9
						if firstBytes[i] == '/' && firstBytes[i-1] == ' ' {
							search := len(firstBytes)
							if search > 64 {
								search = 64 // up to about 60
							}
							for j := i + 1; j < search; j++ {
								k := firstBytes[j]
								if k == '\r' || k == '\n' { // avoid logging \r or \n
									break
								}
								if k == '?' || k == ' ' {
									path = string(firstBytes[i:j])
									errors.LogInfo(ctx, "realPath = "+path)
									if pfb[path] == nil {
										path = ""
									}
									break
								}
							}
							break
						}
					}
				}
			}
			fb := pfb[path]
			if fb == nil {
				return errors.New(`failed to find the default "path" config`).AtWarning()
			}

			ctx, cancel := context.WithCancel(ctx)
			timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)
			ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)

			var conn net.Conn
			if err := retry.ExponentialBackoff(5, 100).On(func() error {
				var dialer net.Dialer
				conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
				if err != nil {
					return err
				}
				return nil
			}); err != nil {
				return errors.New("failed to dial to " + fb.Dest).Base(err).AtWarning()
			}
			defer conn.Close()

			serverReader := buf.NewReader(conn)
			serverWriter := buf.NewWriter(conn)

			postRequest := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
				if fb.Xver != 0 {
					ipType := 4
					remoteAddr, remotePort, err := net.SplitHostPort(connection.RemoteAddr().String())
					if err != nil {
						ipType = 0
					}
					localAddr, localPort, err := net.SplitHostPort(connection.LocalAddr().String())
					if err != nil {
						ipType = 0
					}
					if ipType == 4 {
						for i := 0; i < len(remoteAddr); i++ {
							if remoteAddr[i] == ':' {
								ipType = 6
								break
							}
						}
					}
					pro := buf.New()
					defer pro.Release()
					switch fb.Xver {
					case 1:
						if ipType == 0 {
							pro.Write([]byte("PROXY UNKNOWN\r\n"))
							break
						}
						if ipType == 4 {
							pro.Write([]byte("PROXY TCP4 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						} else {
							pro.Write([]byte("PROXY TCP6 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						}
					case 2:
						pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")) // signature
						if ipType == 0 {
							pro.Write([]byte("\x20\x00\x00\x00")) // v2 + LOCAL + UNSPEC + UNSPEC + 0 bytes
							break
						}
						if ipType == 4 {
							pro.Write([]byte("\x21\x11\x00\x0C")) // v2 + PROXY + AF_INET + STREAM + 12 bytes
							pro.Write(net.ParseIP(remoteAddr).To4())
							pro.Write(net.ParseIP(localAddr).To4())
						} else {
							pro.Write([]byte("\x21\x21\x00\x24")) // v2 + PROXY + AF_INET6 + STREAM + 36 bytes
							pro.Write(net.ParseIP(remoteAddr).To16())
							pro.Write(net.ParseIP(localAddr).To16())
						}
						p1, _ := strconv.ParseUint(remotePort, 10, 16)
						p2, _ := strconv.ParseUint(localPort, 10, 16)
						pro.Write([]byte{byte(p1 >> 8), byte(p1), byte(p2 >> 8), byte(p2)})
					}
					if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro}); err != nil {
						return errors.New("failed to set PROXY protocol v", fb.Xver).Base(err).AtWarning()
					}
				}
				if err := buf.Copy(reader, serverWriter, buf.UpdateActivity(timer)); err != nil {
					return errors.New("failed to fallback request payload").Base(err).AtInfo()
				}
				return nil
			}

			writer := buf.NewWriter(connection)

			getResponse := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
				if err := buf.Copy(serverReader, writer, buf.UpdateActivity(timer)); err != nil {
					return errors.New("failed to deliver response payload").Base(err).AtInfo()
				}
				return nil
			}

			if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(writer))); err != nil {
				common.Interrupt(serverReader)
				common.Interrupt(serverWriter)
				return errors.New("fallback ends").Base(err).AtInfo()
			}
			return nil
		}

		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{
				From:   connection.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			err = errors.New("invalid request from ", connection.RemoteAddr()).Base(err).AtInfo()
		}
		return err
	}

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		errors.LogWarningInner(ctx, err, "unable to set back read deadline")
	}
	errors.LogInfo(ctx, "received request for ", request.Destination())

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.Name = "vless"
	inbound.User = request.User
	inbound.VlessRoute = net.PortFromBytes(userSentID[6:8])

	account := request.User.Account.(*vless.MemoryAccount)

	if account.Reverse != nil && request.Command != protocol.RequestCommandRvs {
		return errors.New("for safety reasons, user " + account.ID.String() + " is not allowed to use forward proxy")
	}

	responseAddons := &encoding.Addons{
		// Flow: requestAddons.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	switch requestAddons.Flow {
	case vless.XRV:
		if account.Flow == requestAddons.Flow {
			inbound.CanSpliceCopy = 2
			switch request.Command {
			case protocol.RequestCommandUDP:
				return errors.New(requestAddons.Flow + " doesn't support UDP").AtWarning()
			case protocol.RequestCommandMux, protocol.RequestCommandRvs:
				inbound.CanSpliceCopy = 3
				fallthrough // we will break Mux connections that contain TCP requests
			case protocol.RequestCommandTCP:
				var t reflect.Type
				var p uintptr
				if commonConn, ok := connection.(*encryption.CommonConn); ok {
					if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
						inbound.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
					}
					t = reflect.TypeOf(commonConn).Elem()
					p = uintptr(unsafe.Pointer(commonConn))
				} else if tlsConn, ok := iConn.(*tls.Conn); ok {
					if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
						return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
					}
					t = reflect.TypeOf(tlsConn.Conn).Elem()
					p = uintptr(unsafe.Pointer(tlsConn.Conn))
				} else if realityConn, ok := iConn.(*reality.Conn); ok {
					t = reflect.TypeOf(realityConn.Conn).Elem()
					p = uintptr(unsafe.Pointer(realityConn.Conn))
				} else {
					return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
				}
				i, _ := t.FieldByName("input")
				r, _ := t.FieldByName("rawInput")
				input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
				rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
			}
		} else {
			return errors.New("account " + account.ID.String() + " is not able to use the flow " + requestAddons.Flow).AtWarning()
		}
	case "":
		inbound.CanSpliceCopy = 3
		if account.Flow == vless.XRV && (request.Command == protocol.RequestCommandTCP || isMuxAndNotXUDP(request, first)) {
			return errors.New("account " + account.ID.String() + " is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters.").AtWarning()
		}
	default:
		return errors.New("unknown request flow " + requestAddons.Flow).AtWarning()
	}

	if request.Command != protocol.RequestCommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     request.Destination(),
			Status: log.AccessAccepted,
			Reason: "",
			Email:  request.User.Email,
		})
	} else if account.Flow == vless.XRV {
		ctx = session.ContextWithAllowedNetwork(ctx, net.Network_UDP)
	}

	trafficState := proxy.NewTrafficState(userSentID)
	clientReader := encoding.DecodeBodyAddons(reader, request, requestAddons)
	if requestAddons.Flow == vless.XRV {
		clientReader = proxy.NewVisionReader(clientReader, trafficState, true, ctx, connection, input, rawInput, nil)
	}

	bufferWriter := buf.NewBufferedWriter(buf.NewWriter(connection))
	if err := encoding.EncodeResponseHeader(bufferWriter, request, responseAddons); err != nil {
		return errors.New("failed to encode response header").Base(err).AtWarning()
	}
	clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, false, ctx, connection, nil)
	bufferWriter.SetFlushNext()

	if request.Command == protocol.RequestCommandRvs {
		r, err := h.GetReverse(account)
		if err != nil {
			return err
		}
		return r.NewMux(ctx, dispatcher.WrapLink(ctx, h.policyManager, h.stats, &transport.Link{Reader: clientReader, Writer: clientWriter}), h.observer)
	}

	// Virtual network branch. When the inbound was configured with
	// virtualNetwork.enabled=true, every authenticated VLESS connection
	// on this inbound is treated as an L3 tunnel: the stream carries
	// length-prefixed raw IPv4 packets after the VLESS response header.
	// See proxy/vless/virtualnet for the protocol details.
	//
	// This branch only runs when h.vnet != nil. With h.vnet == nil
	// (vanilla VLESS) the control falls through to the legacy
	// DispatchLink path, preserving existing behaviour.
	if h.vnet != nil {
		// We require flow="" for the virtual network because XTLS
		// Vision splices raw TCP — incompatible with our framing.
		if requestAddons.Flow != "" {
			return errors.New("virtualNetwork: unsupported flow " + requestAddons.Flow).AtWarning()
		}
		if request.Command != protocol.RequestCommandTCP {
			return errors.New("virtualNetwork: only TCP command is supported").AtWarning()
		}
		return h.serveVirtualNetwork(ctx, account, clientReader, clientWriter, connection)
	}

	if err := dispatch.DispatchLink(ctx, request.Destination(), &transport.Link{
		Reader: clientReader,
		Writer: clientWriter},
	); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil
}

// serveVirtualNetwork turns the VLESS post-handshake stream into an L3
// tunnel: the user is assigned (or reuses) a virtual IP, their stream is
// registered with the switch, and this function blocks until the stream
// closes or the switch is torn down.
//
// The VLESS response header was already written by the caller via
// bufferWriter, so clientReader/clientWriter carry only body bytes from
// this point on; they are packaged up as an io.ReadWriteCloser for the
// switch via virtualnet.StreamConn.
func (h *Handler) serveVirtualNetwork(
	ctx context.Context,
	account *vless.MemoryAccount,
	clientReader buf.Reader,
	clientWriter buf.Writer,
	connection stat.Connection,
) error {
	ip, err := h.vnet.IPAM().Assign(account.ID.String())
	if err != nil {
		return errors.New("virtualNetwork: assign IP").Base(err)
	}

	// Rewrite the session.Inbound.Source so xray routing rules that key
	// on sourceIP (e.g. "10.0.0.2") match against the user's virtual IP
	// for the lifetime of this connection. This is the "Virtual IPs
	// must appear as source IP in xray's routing context" requirement.
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Source = net.Destination{
			Network: net.Network_TCP,
			Address: net.IPAddress(ip.AsSlice()),
			Port:    0,
		}
		// Capture the inbound tag for use by virtualNetworkConnHandler.
		// proxyman fills inbound.Tag on the first Process invocation;
		// the synthesised sub-flow ConnHandler runs in goroutines that
		// don't see this ctx, so we stash the tag on the Handler the
		// first time we observe it. All Process calls for the same
		// inbound see the same tag, so racing Stores are idempotent.
		if inbound.Tag != "" && h.inboundTag.Load() == nil {
			tag := inbound.Tag
			h.inboundTag.Store(&tag)
		}
	}

	stream := virtualnet.NewStreamConn(clientReader, clientWriter, connection)

	// Announce the assigned virtual IP to the client as a one-shot
	// 4-byte preamble before any framed traffic. The client's L3 mode
	// state machine reads exactly PreambleSize bytes from the stream,
	// assigns them to its TUN, and then enters framed-packet mode.
	ip4 := ip.As4()
	if err := virtualnet.WriteIPPreamble(stream, ip4); err != nil {
		return errors.New("virtualNetwork: write IP preamble").Base(err)
	}

	ep, err := h.vnet.Register(ip, account.ID.String(), stream)
	if err != nil {
		return errors.New("virtualNetwork: register").Base(err)
	}
	errors.LogInfo(ctx, "virtualNetwork: user "+account.ID.String()+" connected as "+ip.String())

	// Block until the endpoint's read loop exits or the outer ctx is
	// cancelled (the VLESS connection handler cancels ctx on client
	// disconnect).
	done := make(chan struct{})
	go func() {
		ep.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		_ = ep.Close()
	}
	errors.LogInfo(ctx, "virtualNetwork: user "+account.ID.String()+" disconnected from "+ip.String())
	return nil
}

type Reverse struct {
	tag    string
	picker *reverse.StaticMuxPicker
	client *mux.ClientManager
}

func (r *Reverse) Tag() string {
	return r.tag
}

func (r *Reverse) NewMux(ctx context.Context, link *transport.Link, observer features.Feature) error {
	muxClient, err := mux.NewClientWorker(*link, mux.ClientStrategy{})
	if err != nil {
		return errors.New("failed to create mux client worker").Base(err).AtWarning()
	}
	worker, err := reverse.NewPortalWorker(muxClient)
	if err != nil {
		return errors.New("failed to create portal worker").Base(err).AtWarning()
	}
	r.picker.AddWorker(worker)
	if burstObs, ok := observer.(extension.BurstObservatory); ok {
		go burstObs.Check([]string{r.Tag()})
	}
	select {
	case <-ctx.Done():
	case <-muxClient.WaitClosed():
	}
	return nil
}

func (r *Reverse) Dispatch(ctx context.Context, link *transport.Link) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob != nil {
		if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
			link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
			link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		}
		r.client.Dispatch(session.ContextWithIsReverseMux(ctx, true), link)
	}
}

func (r *Reverse) Start() error {
	return nil
}

func (r *Reverse) Close() error {
	return nil
}

func (r *Reverse) SenderSettings() *serial.TypedMessage {
	return nil
}

func (r *Reverse) ProxySettings() *serial.TypedMessage {
	return nil
}
