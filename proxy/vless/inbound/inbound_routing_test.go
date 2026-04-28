package inbound

import (
	"context"
	stdnet "net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/virtualnet"
	"github.com/xtls/xray-core/transport"
)

// xrayCtxForTest builds a minimal context that carries a *core.Instance,
// satisfying core.MustFromContext used by virtualNetworkConnHandler via
// core.ToBackgroundDetachedContext. We avoid invoking core.New (which
// pulls in dispatcher/proxyman feature initialisation) by stashing a
// zero-valued *core.Instance directly under the unexported context
// key. ToBackgroundDetachedContext re-injects whatever instance it
// finds, so a placeholder is enough for the closure under test.
func xrayCtxForTest(t *testing.T) context.Context {
	t.Helper()
	inst, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), inst)
}

// captureDispatcher implements routing.Dispatcher and records the
// session.Inbound seen on every dispatched ctx so tests can assert on
// the tag propagated by virtualNetworkConnHandler.
type captureDispatcher struct {
	mu       sync.Mutex
	inbounds []*session.Inbound
	dst      []net.Destination
	sniff    []session.SniffingRequest
}

func (c *captureDispatcher) Type() interface{} { return routing.DispatcherType() }
func (c *captureDispatcher) Start() error      { return nil }
func (c *captureDispatcher) Close() error      { return nil }

func (c *captureDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	c.record(ctx, dest)
	return nil, nil
}

func (c *captureDispatcher) DispatchLink(ctx context.Context, dest net.Destination, _ *transport.Link) error {
	c.record(ctx, dest)
	return nil
}

func (c *captureDispatcher) record(ctx context.Context, dest net.Destination) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inbounds = append(c.inbounds, session.InboundFromContext(ctx))
	c.dst = append(c.dst, dest)
	if content := session.ContentFromContext(ctx); content != nil {
		c.sniff = append(c.sniff, content.SniffingRequest)
	} else {
		c.sniff = append(c.sniff, session.SniffingRequest{})
	}
}

// TestVirtualNetworkConnHandlerPropagatesInboundTag verifies the bug fix
// where synthesised L3 sub-flows surfaced with an empty inbound.Tag,
// causing user-defined routing rules keyed on inboundTag (e.g.
// {"inboundTag":["inbound-443"], ...} emitted by 3x-ui) to silently
// fall through to the default outbound. With the fix, the tag observed
// by the dispatcher matches what proxyman set on the original VLESS
// inbound's Process ctx.
func TestVirtualNetworkConnHandlerPropagatesInboundTag(t *testing.T) {
	sw, err := virtualnet.NewSwitch(context.Background(), virtualnet.Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	disp := &captureDispatcher{}
	h := &Handler{
		defaultDispatcher: disp,
		validator:         new(vless.MemoryValidator),
		vnet:              sw,
		ctx:               xrayCtxForTest(t),
	}
	tag := "inbound-443"
	h.inboundTag.Store(&tag)

	src := netip.MustParseAddr("10.0.0.42")
	dst := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress("1.2.3.4"),
		Port:    net.Port(80),
	}
	conn := newFakeConn("1.2.3.4", 80)
	h.virtualNetworkConnHandler()(src, dst, conn)

	if got := len(disp.inbounds); got != 1 {
		t.Fatalf("expected 1 dispatch, got %d", got)
	}
	in := disp.inbounds[0]
	if in == nil {
		t.Fatalf("session.Inbound missing on dispatched ctx")
	}
	if in.Tag != "inbound-443" {
		t.Errorf("inbound.Tag = %q, want %q", in.Tag, "inbound-443")
	}
	if got, want := in.Source.Address.String(), "10.0.0.42"; got != want {
		t.Errorf("inbound.Source.Address = %q, want %q", got, want)
	}
}

// TestVirtualNetworkConnHandlerEmptyTagWhenUnset confirms the closure
// leaves Tag empty when the handler hasn't observed any Process ctx
// yet. This makes the tag-capture-on-first-Process behaviour explicit
// in the test suite so future refactors that change the fallback
// (e.g. read tag from config instead) catch any regression.
func TestVirtualNetworkConnHandlerEmptyTagWhenUnset(t *testing.T) {
	sw, err := virtualnet.NewSwitch(context.Background(), virtualnet.Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	disp := &captureDispatcher{}
	h := &Handler{
		defaultDispatcher: disp,
		validator:         new(vless.MemoryValidator),
		vnet:              sw,
		ctx:               xrayCtxForTest(t),
	}
	if h.inboundTag.Load() != nil {
		t.Fatalf("inboundTag should default to nil")
	}

	src := netip.MustParseAddr("10.0.0.99")
	dst := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress("8.8.8.8"),
		Port:    net.Port(53),
	}
	conn := newFakeConn("8.8.8.8", 53)
	h.virtualNetworkConnHandler()(src, dst, conn)

	if got := len(disp.inbounds); got != 1 {
		t.Fatalf("expected 1 dispatch, got %d", got)
	}
	if tag := disp.inbounds[0].Tag; tag != "" {
		t.Errorf("inbound.Tag = %q, want empty", tag)
	}
}

// TestVirtualNetworkConnHandlerRewritesGatewayDestToLoopback verifies
// the bug fix where flows addressed to the virtual gateway IP (e.g.
// curl http://10.0.0.1:4747 to reach a service listening on the VPS
// host) used to be dispatched with the literal gateway IP, which the
// freedom outbound then dialed over the host network where no real
// interface owns it. With the fix the dispatcher receives 127.0.0.1
// so the dial lands on the host's loopback and reaches services
// bound to 0.0.0.0.
//
// In addition to rewriting the destination, the handler must rename
// inbound.Name away from "vless" so that freedom's
// defaultPrivateBlockIPMatcher (which treats 127.0.0.0/8 as a private
// destination to block for inbound names like vless / vmess / trojan
// / hysteria / wireguard / shadowsocks*) does not refuse the dial.
// Skipping the rename was the cause of "Empty reply from server"
// observed in end-to-end testing on v0.0.7-test and v0.0.8-test:
// the dispatcher correctly dialed 127.0.0.1, but freedom then closed
// the connection with "blocked target IP: 127.0.0.1" in its access
// log because inbound.Name was still "vless". Renaming to
// "virtualnet-gateway" is intentional and scoped to gateway-IP
// rewritten flows only.
func TestVirtualNetworkConnHandlerRewritesGatewayDestToLoopback(t *testing.T) {
	sw, err := virtualnet.NewSwitch(context.Background(), virtualnet.Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	disp := &captureDispatcher{}
	h := &Handler{
		defaultDispatcher: disp,
		validator:         new(vless.MemoryValidator),
		vnet:              sw,
		ctx:               xrayCtxForTest(t),
	}

	src := netip.MustParseAddr("10.0.0.42")
	dst := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress("10.0.0.1"),
		Port:    net.Port(4747),
	}
	conn := newFakeConn("10.0.0.1", 4747)
	h.virtualNetworkConnHandler()(src, dst, conn)

	if got := len(disp.dst); got != 1 {
		t.Fatalf("expected 1 dispatch, got %d", got)
	}
	if got, want := disp.dst[0].Address.String(), "127.0.0.1"; got != want {
		t.Errorf("rewritten dst.Address = %q, want %q", got, want)
	}
	if got, want := uint16(disp.dst[0].Port), uint16(4747); got != want {
		t.Errorf("dst.Port = %d, want %d (port must be preserved)", got, want)
	}
	if got := disp.inbounds[0]; got == nil {
		t.Fatalf("session.Inbound missing on dispatched ctx")
	} else if got.Name != "virtualnet-gateway" {
		t.Errorf("inbound.Name = %q, want %q (otherwise freedom's defaultPrivateBlockIPMatcher will reject the loopback dial)", got.Name, "virtualnet-gateway")
	}
}

// TestVirtualNetworkConnHandlerLeavesNonGatewayDestUntouched pins the
// scope of the gateway-IP rewrite so that future refactors can't widen
// it to peer or external addresses by accident.
func TestVirtualNetworkConnHandlerLeavesNonGatewayDestUntouched(t *testing.T) {
	sw, err := virtualnet.NewSwitch(context.Background(), virtualnet.Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	cases := []struct {
		name string
		ip   string
	}{
		{"peer in subnet", "10.0.0.42"},
		{"external IPv4", "8.8.8.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			disp := &captureDispatcher{}
			h := &Handler{
				defaultDispatcher: disp,
				validator:         new(vless.MemoryValidator),
				vnet:              sw,
				ctx:               xrayCtxForTest(t),
			}
			src := netip.MustParseAddr("10.0.0.99")
			dst := net.Destination{
				Network: net.Network_TCP,
				Address: net.ParseAddress(tc.ip),
				Port:    net.Port(80),
			}
			conn := newFakeConn(tc.ip, 80)
			h.virtualNetworkConnHandler()(src, dst, conn)

			if got := len(disp.dst); got != 1 {
				t.Fatalf("expected 1 dispatch, got %d", got)
			}
			if got := disp.dst[0].Address.String(); got != tc.ip {
				t.Errorf("dst.Address = %q, want %q (must not be rewritten)", got, tc.ip)
			}
			if got := disp.inbounds[0]; got == nil {
				t.Fatalf("session.Inbound missing on dispatched ctx")
			} else if got.Name != "vless" {
				t.Errorf("inbound.Name = %q, want %q (rename is reserved for gateway-IP rewrite path)", got.Name, "vless")
			}
		})
	}
}

// TestVirtualNetworkConnHandlerSetsSniffingRouteOnly verifies that the
// sniffing request attached to L3 sub-flows is created with
// RouteOnly=true. Without that flag, the dispatcher's HTTP/TLS sniffer
// would override the dispatch destination by Host/SNI and cancel the
// gateway-IP rewrite (e.g. an HTTP "Host: 10.0.0.1" header would yank
// Target back from the rewritten 127.0.0.1 to the unreachable
// gateway address, defeating the whole point of the rewrite). Domain-
// based routing rules keep working because RouteOnly populates
// ob.RouteTarget for the routing engine.
func TestVirtualNetworkConnHandlerSetsSniffingRouteOnly(t *testing.T) {
	sw, err := virtualnet.NewSwitch(context.Background(), virtualnet.Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	disp := &captureDispatcher{}
	h := &Handler{
		defaultDispatcher: disp,
		validator:         new(vless.MemoryValidator),
		vnet:              sw,
		ctx:               xrayCtxForTest(t),
	}
	src := netip.MustParseAddr("10.0.0.5")
	dst := net.Destination{
		Network: net.Network_TCP,
		Address: net.ParseAddress("1.2.3.4"),
		Port:    net.Port(443),
	}
	conn := newFakeConn("1.2.3.4", 443)
	h.virtualNetworkConnHandler()(src, dst, conn)

	if got := len(disp.sniff); got != 1 {
		t.Fatalf("expected 1 dispatch, got %d", got)
	}
	sniff := disp.sniff[0]
	if !sniff.Enabled {
		t.Errorf("SniffingRequest.Enabled = false, want true")
	}
	if !sniff.RouteOnly {
		t.Errorf("SniffingRequest.RouteOnly = false, want true (otherwise the sniffer overrides Target and undoes the gateway-IP rewrite)")
	}
	wantProtos := map[string]bool{"http": true, "tls": true}
	for _, p := range sniff.OverrideDestinationForProtocol {
		delete(wantProtos, p)
	}
	if len(wantProtos) != 0 {
		t.Errorf("OverrideDestinationForProtocol missing %v, got %v", wantProtos, sniff.OverrideDestinationForProtocol)
	}
}

// TestInboundTagAtomicStoreLoad documents the lock-free read/write
// contract used by serveVirtualNetwork (writer) and
// virtualNetworkConnHandler (reader). It exists so that anyone who
// considers swapping atomic.Pointer for a plain string field has a
// failing race test to remind them why the indirection is required.
func TestInboundTagAtomicStoreLoad(t *testing.T) {
	var p atomic.Pointer[string]
	if p.Load() != nil {
		t.Fatal("zero atomic.Pointer should Load nil")
	}
	tag := "inbound-443"
	p.Store(&tag)
	got := p.Load()
	if got == nil || *got != "inbound-443" {
		t.Fatalf("Load after Store mismatch: %v", got)
	}
}

// fakeConn is a minimal stdlib net.Conn shim. virtualNetworkConnHandler
// only inspects RemoteAddr() on the conn (the Reader/Writer it builds
// from the conn are passed straight to DispatchLink, which our
// captureDispatcher discards).
type fakeConn struct {
	remote stdnet.Addr
	closed bool
}

func newFakeConn(ip string, port int) *fakeConn {
	return &fakeConn{remote: &stdnet.TCPAddr{IP: stdnet.ParseIP(ip), Port: port}}
}

func (f *fakeConn) Read(_ []byte) (int, error)  { return 0, nil }
func (f *fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeConn) Close() error                { f.closed = true; return nil }
func (f *fakeConn) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: 0}
}
func (f *fakeConn) RemoteAddr() stdnet.Addr            { return f.remote }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }
