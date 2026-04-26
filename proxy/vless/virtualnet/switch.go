package virtualnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/wireguard/gvisortun"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// defaultMTU for the virtual TUN. 1420 matches the WireGuard default and
// leaves room for transport framing over the VLESS stream.
const defaultMTU = 1420

// ConnHandler is invoked by the Switch whenever a new TCP/UDP flow from a
// user terminates at the virtual gateway and should be proxied further.
// srcVirtIP identifies the originating user (so the caller can build an
// xray session.Inbound with the correct Source for routing rules).
// dst is the original L4 destination the user addressed.
//
// The conn argument is an already-established gVisor userspace socket
// (TCP) or PacketConn-ish net.Conn (UDP). The handler is responsible for
// closing it when done.
//
// Phase 3 of the implementation wires this to routing.Dispatcher. Phase 1
// keeps the hook abstract so the virtualnet package has no dependency on
// xray's routing feature.
type ConnHandler func(srcVirtIP netip.Addr, dst xnet.Destination, conn net.Conn)

// Switch is the L3 virtual network: it owns the gVisor userspace stack,
// an endpoint routing table keyed by destination IP, and the dispatch
// hook for non-user-destined traffic.
//
// A Switch is created with NewSwitch, then endpoints are added as users
// authenticate via Register. On shutdown, Close() tears the stack down
// and closes every registered endpoint's stream.
type Switch struct {
	subnet    netip.Prefix
	gatewayIP netip.Addr

	// IP assignment is owned by the switch; phase 2 gives it a
	// real implementation. nil means no automatic assignment.
	ipam *IPAM

	// endpoints maps virtual IP -> *Endpoint. Reads are on the packet
	// hot path so we use an RWMutex.
	mu        sync.RWMutex
	endpoints map[netip.Addr]*Endpoint
	closed    bool

	// gVisor userspace stack and its tun half. tunDev.Write() injects a
	// packet into the stack; tunDev.Read() returns packets the stack
	// wants to send out (e.g. SYN/ACK from a gateway TCP endpoint back
	// to the originating user).
	tunDev   tun.Device
	gNet     *gvisortun.Net
	gStack   *stack.Stack
	nicID    tcpip.NICID
	tunMTU   int
	handler  ConnHandler
	udpConns *udpConnTable

	// ctx is the base context for the switch; cancelled by Close().
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config controls how a Switch is constructed.
type Config struct {
	// Subnet is the user-facing subnet in CIDR form (e.g. 10.0.0.0/24).
	// The first usable host (subnet.Addr().Next()) is reserved as the
	// gateway that gVisor binds to.
	Subnet netip.Prefix

	// PersistMapping keeps UUID->IP assignments stable for the lifetime
	// of the process. When false the IPAM still persists mappings in
	// memory — the flag only affects future persistence backends.
	PersistMapping bool

	// MTU of the virtual TUN. Zero means defaultMTU.
	MTU int

	// Handler is invoked for every TCP/UDP flow that reaches the
	// virtual gateway and needs external forwarding. May be nil, in
	// which case such flows are silently dropped (useful for tests).
	Handler ConnHandler
}

// NewSwitch builds a Switch with its own gVisor netstack bound to the
// subnet's gateway address. It does not register any endpoints.
func NewSwitch(parent context.Context, cfg Config) (*Switch, error) {
	if !cfg.Subnet.IsValid() {
		return nil, errors.New("virtualnet: Config.Subnet is invalid")
	}
	if !cfg.Subnet.Addr().Is4() {
		return nil, errors.New("virtualnet: only IPv4 subnets are supported")
	}
	// Gateway is the first host after the network address, matching
	// typical /24 conventions (e.g. 10.0.0.1 for 10.0.0.0/24).
	gateway := cfg.Subnet.Addr().Next()
	if !cfg.Subnet.Contains(gateway) {
		return nil, errors.New("virtualnet: subnet is too small for a gateway")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	// Promiscuous=true because we want the gVisor stack to accept
	// packets destined to IPs other than the gateway (this lets us
	// "spoof" source IPs into routing context via the gateway's TCP/UDP
	// forwarders). It mirrors what proxy/wireguard does.
	dev, gnet, gstack, err := gvisortun.CreateNetTUN([]netip.Addr{gateway}, mtu, true)
	if err != nil {
		return nil, fmt.Errorf("virtualnet: CreateNetTUN: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	sw := &Switch{
		subnet:    cfg.Subnet,
		gatewayIP: gateway,
		ipam:      NewIPAM(cfg.Subnet, cfg.PersistMapping),
		endpoints: make(map[netip.Addr]*Endpoint),
		tunDev:    dev,
		gNet:      gnet,
		gStack:    gstack,
		nicID:     1,
		tunMTU:    mtu,
		handler:   cfg.Handler,
		udpConns:  newUDPConnTable(),
		ctx:       ctx,
		cancel:    cancel,
	}

	if err := sw.installForwarders(); err != nil {
		_ = dev.Close()
		cancel()
		return nil, err
	}

	// Start the goroutine that pulls outbound packets from the gVisor
	// stack and delivers them to the matching endpoint by destination
	// IP.
	sw.wg.Add(1)
	go sw.tunReadLoop()

	return sw, nil
}

// Subnet returns the CIDR the switch manages. Useful for the config
// wire-up to compare against an existing switch on config reload.
func (s *Switch) Subnet() netip.Prefix { return s.subnet }

// Gateway returns the gVisor-bound gateway IP (subnet.Addr()+1).
func (s *Switch) Gateway() netip.Addr { return s.gatewayIP }

// IPAM returns the IP address manager so callers can look up or assign
// per-UUID addresses.
func (s *Switch) IPAM() *IPAM { return s.ipam }

// Register attaches a user's VLESS stream to the switch at the given
// virtual IP. The returned *Endpoint spawns its own goroutine to read
// packets from the stream; the caller should block on endpoint.Wait()
// for the lifetime of the VLESS connection.
func (s *Switch) Register(virtIP netip.Addr, uuid string, stream io.ReadWriteCloser) (*Endpoint, error) {
	if !s.subnet.Contains(virtIP) {
		return nil, fmt.Errorf("virtualnet: IP %s is outside subnet %s", virtIP, s.subnet)
	}
	if virtIP == s.gatewayIP {
		return nil, errors.New("virtualnet: cannot register gateway IP as a user")
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("virtualnet: switch is closed")
	}
	if prev, exists := s.endpoints[virtIP]; exists {
		// Evict the old endpoint — the user reconnected. We do this
		// under the lock so there is never a window where two endpoints
		// share an IP. Closing is best-effort.
		s.mu.Unlock()
		_ = prev.Close()
		s.mu.Lock()
		// Re-check state; prev.Close may have run concurrently with a
		// shutdown.
		if s.closed {
			s.mu.Unlock()
			return nil, errors.New("virtualnet: switch is closed")
		}
	}

	ctx, cancel := context.WithCancel(s.ctx)
	ep := &Endpoint{
		IP:     virtIP,
		UUID:   uuid,
		stream: stream,
		sw:     s,
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	s.endpoints[virtIP] = ep
	s.mu.Unlock()

	go ep.run()
	return ep, nil
}

// unregister removes an endpoint from the routing table. It is called by
// Endpoint.Close; external callers should use Endpoint.Close instead.
// The check "current endpoint pointer matches" avoids racing with a
// concurrent reconnection that has already replaced this slot.
func (s *Switch) unregister(virtIP netip.Addr, ep *Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.endpoints[virtIP]; ok && cur == ep {
		delete(s.endpoints, virtIP)
	}
}

// lookup returns the endpoint currently registered at virtIP, or nil.
func (s *Switch) lookup(virtIP netip.Addr) *Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.endpoints[virtIP]
}

// forward is the switch's L3 fast path, invoked by Endpoint.run for every
// packet it reads from a user.
//
//   - Packet destined to another user's virtual IP -> copy directly to
//     that user's endpoint stream (no gVisor, no dispatcher). This is the
//     peer-to-peer leg of the task.
//
//   - Packet destined to the gateway IP, or to any other address -> inject
//     into gVisor; TCP/UDP forwarders will fire and eventually call
//     handler() with the matching xray outbound.
//
//   - Anything that fails to parse as IPv4 is dropped. This mirrors how
//     a real L3 switch treats non-IP ethertypes.
func (s *Switch) forward(src *Endpoint, pkt []byte) {
	h, ok := parseIPv4Header(pkt)
	if !ok {
		return
	}

	// Anti-spoofing: the source IP in the header must match the virtual
	// IP we assigned to this user. Otherwise xray routing rules keyed
	// on sourceIP would be trivially bypassable.
	if netip.AddrFrom4(h.src) != src.IP {
		return
	}

	dst := netip.AddrFrom4(h.dst)

	// Peer-to-peer: another user on this switch owns the destination.
	if peer := s.lookup(dst); peer != nil && peer != src {
		_ = peer.Send(pkt)
		return
	}

	// Everything else goes into the gVisor stack. The tun device's
	// Write method parses the IP version for us.
	_, _ = s.tunDev.Write([][]byte{pkt}, 0)
}

// tunReadLoop drains the gVisor tun of outbound packets and routes them
// to the endpoint with the matching destination IP. This is how TCP
// SYN/ACK, UDP replies, etc. produced by the server-side gVisor stack
// reach the originating user.
func (s *Switch) tunReadLoop() {
	defer s.wg.Done()

	const batch = 1
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, s.tunMTU+frameHeaderSize)
	}

	for {
		n, err := s.tunDev.Read(bufs, sizes, 0)
		if err != nil {
			// Stack shut down.
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			h, ok := parseIPv4Header(pkt)
			if !ok {
				continue
			}
			if ep := s.lookup(netip.AddrFrom4(h.dst)); ep != nil {
				// Copy before Send because the buffer is about to be
				// reused by the next Read call.
				cp := make([]byte, len(pkt))
				copy(cp, pkt)
				_ = ep.Send(cp)
			}
		}
	}
}

// installForwarders wires TCP and UDP handlers on the gVisor stack so
// that every flow destined to the virtual gateway (or anywhere else that
// lands in the stack) surfaces as a net.Conn we can hand to the
// ConnHandler.
func (s *Switch) installForwarders() error {
	tcpForwarder := tcp.NewForwarder(s.gStack, 0, 1024, func(r *tcp.ForwarderRequest) {
		s.handleTCPRequest(r)
	})
	s.gStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// UDP: we build our own demuxed "conn" per 5-tuple similar to the
	// wireguard server, but simpler — the handler closes the conn when
	// finished and we don't keep long-lived pools here.
	udpForwarder := udp.NewForwarder(s.gStack, func(r *udp.ForwarderRequest) bool {
		s.handleUDPRequest(r)
		return true
	})
	s.gStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return nil
}

// handleTCPRequest terminates a TCP handshake inside gVisor and hands the
// resulting userspace net.Conn to the ConnHandler, tagged with the real
// source user IP so xray routing rules can match on it.
func (s *Switch) handleTCPRequest(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, gerr := r.CreateEndpoint(&wq)
	if gerr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	opts := ep.SocketOptions()
	opts.SetKeepAlive(false)

	conn := gonet.NewTCPConn(&wq, ep)
	srcIP, ok := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok {
		_ = conn.Close()
		return
	}
	srcIP = srcIP.Unmap()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		_ = conn.Close()
		return
	}
	dstIP = dstIP.Unmap()

	dst := xnet.TCPDestination(xnet.IPAddress(dstIP.AsSlice()), xnet.Port(id.LocalPort))
	if s.handler == nil {
		_ = conn.Close()
		return
	}
	go s.handler(srcIP, dst, conn)
}

// handleUDPRequest mirrors handleTCPRequest for UDP. gVisor's
// udp.NewForwarder synthesises a PacketConn via gonet.NewUDPConn; we cast
// it to net.Conn (it already implements it) and hand it off.
func (s *Switch) handleUDPRequest(r *udp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, gerr := r.CreateEndpoint(&wq)
	if gerr != nil {
		return
	}
	conn := gonet.NewUDPConn(&wq, ep)

	srcIP, ok := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok {
		_ = conn.Close()
		return
	}
	srcIP = srcIP.Unmap()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		_ = conn.Close()
		return
	}
	dstIP = dstIP.Unmap()

	dst := xnet.UDPDestination(xnet.IPAddress(dstIP.AsSlice()), xnet.Port(id.LocalPort))
	if s.handler == nil {
		_ = conn.Close()
		return
	}
	go s.handler(srcIP, dst, conn)
}

// Close releases all switch resources. After Close, Register returns an
// error and all existing endpoints are shut down.
func (s *Switch) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	eps := make([]*Endpoint, 0, len(s.endpoints))
	for _, ep := range s.endpoints {
		eps = append(eps, ep)
	}
	s.mu.Unlock()

	for _, ep := range eps {
		_ = ep.Close()
	}
	s.cancel()
	_ = s.tunDev.Close()
	s.wg.Wait()
	return nil
}

// udpConnTable is a placeholder for a future per-flow UDP conn pool; it
// exists now so we can plumb it through without later needing to change
// the switch's struct layout. The forwarder's per-request endpoints are
// sufficient for the current implementation.
type udpConnTable struct{}

func newUDPConnTable() *udpConnTable { return &udpConnTable{} }
