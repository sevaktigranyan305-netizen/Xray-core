//go:build windows

package l3client

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// init overrides wireguard/tun's adapter type so the wintun adapter we
// create shows up under our own name in tooling such as `wintun.exe
// list` or Sysinternals' tdi/etwview, rather than impersonating
// WireGuard. The variable is package-level in golang.zx2c4.com/wireguard/tun
// and is read once per CreateTUN call, so writing it from our init is
// race-free as long as no caller invokes wgtun.CreateTUN concurrently
// with import.
func init() {
	wgtun.WintunTunnelType = "v2rayV"
}

// windowsDevice is the Windows backend for Device. It bridges
// wireguard/tun's wintun-based NativeTun (which delivers single packets
// with no link-layer header offset) and configures interface addresses
// and routes via the Windows IP Helper API exposed by
// golang.zx2c4.com/wireguard/windows/tunnel/winipcfg.
//
// We use winipcfg directly rather than shelling out to `netsh` because
// netsh's behaviour, exit codes, and even argument grammar drift across
// Windows 10/11 minor releases, while the IP Helper API is part of the
// stable Win32 platform contract. winipcfg is also significantly faster
// (no process launch per command) and lets us delete routes by exact
// destination+nextHop tuple, which `netsh` can't do reliably when
// multiple matching routes exist.
type windowsDevice struct {
	tun       wgtun.Device
	nativeTun *wgtun.NativeTun
	luid      winipcfg.LUID
	name      string
	mtu       int
	ipPrefix  netip.Prefix

	// underlayRoutes are routes we installed on interfaces other than
	// our own TUN — currently just the /32 host route to the VLESS
	// server through the pre-existing default gateway. These need
	// explicit DeleteRoute on Close because FlushRoutes(AF_INET) is
	// scoped to a single LUID and we must not flush the user's real
	// underlay routes.
	underlayRoutes []underlayRoute

	// readBufMu serialises Read so that the package's single-packet
	// contract is preserved even if a buggy caller calls Read from
	// multiple goroutines. wireguard/tun's Read is documented as
	// single-threaded; we reuse a per-device scratch buffer here so
	// the read path does not allocate per packet.
	readBufMu sync.Mutex
	readBufs  [1][]byte
	readSizes [1]int
}

// underlayRoute records routes we installed on an interface other than
// our own TUN, so Close() can remove exactly the entries we added
// without disturbing unrelated routes the user may have configured on
// the same underlay interface.
type underlayRoute struct {
	luid    winipcfg.LUID
	dest    netip.Prefix
	nextHop netip.Addr
}

// winInterfaceMetric is the metric we assign to every route we add. 0
// asks Windows to pick the per-interface metric, which matches what
// `netsh interface ipv4 add route … metric=default` does and gives our
// /1 default-half routes priority over the user's existing 0.0.0.0/0
// only because they are strictly more specific (1-bit prefix vs 0-bit).
const winInterfaceMetric uint32 = 0

func newDevice(cfg deviceConfig) (Device, error) {
	if !cfg.IP.Is4() {
		return nil, errors.New("l3client: only IPv4 virtual addresses are supported")
	}
	if !cfg.Subnet.Addr().Is4() {
		return nil, errors.New("l3client: only IPv4 subnets are supported")
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = MTU
	}
	name := cfg.Name
	if name == "" {
		name = "v2rayV"
	}

	tun, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("l3client: create wintun adapter %q: %w", name, err)
	}
	nativeTun, ok := tun.(*wgtun.NativeTun)
	if !ok {
		_ = tun.Close()
		return nil, errors.New("l3client: unexpected tun device type on windows (not *wgtun.NativeTun)")
	}
	realName, err := tun.Name()
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: tun.Name: %w", err)
	}
	luid := winipcfg.LUID(nativeTun.LUID())

	d := &windowsDevice{
		tun:       tun,
		nativeTun: nativeTun,
		luid:      luid,
		name:      realName,
		mtu:       mtu,
		ipPrefix:  netip.PrefixFrom(cfg.IP, cfg.Subnet.Bits()),
	}
	// MTU+128 leaves slack for any oversized packet that slips through
	// upstream; wintun itself does not prepend a link-layer header so
	// we do not reserve offset bytes here, unlike linux (virtio-net-hdr)
	// or darwin (4-byte address-family).
	d.readBufs[0] = make([]byte, mtu+128)

	// SetIPAddressesForFamily flushes existing IPv4 addresses on the
	// adapter and installs ours. Since the adapter is brand new this
	// is effectively just an Add, but using SetIPAddressesForFamily is
	// idempotent if newDevice is somehow called twice for the same
	// adapter name (wintun reuses adapters by name).
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{d.ipPrefix}); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("l3client: SetIPAddresses %s: %w", d.ipPrefix, err)
	}

	// Add an explicit route for the virtual subnet via the TUN. Windows
	// usually synthesises a connected route from the assigned address,
	// but stating it explicitly matches the behaviour of the linux and
	// darwin backends and protects against the synthesised route being
	// suppressed by interface metric tuning.
	subnet := cfg.Subnet.Masked()
	if err := luid.AddRoute(subnet, netip.IPv4Unspecified(), winInterfaceMetric); err != nil &&
		!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		_ = d.Close()
		return nil, fmt.Errorf("l3client: AddRoute subnet %s: %w", subnet, err)
	}

	if cfg.DefaultRoute {
		if err := d.installDefaultRoute(cfg.ServerIP); err != nil {
			_ = d.Close()
			return nil, err
		}
	}

	return d, nil
}

// installDefaultRoute is the Windows analogue of the linux/darwin
// default-route hijack: install a /32 host route to the VLESS server
// via the existing default gateway (so VLESS packets keep flowing on
// the underlay), then add 0.0.0.0/1 and 128.0.0.0/1 via our TUN. These
// /1 routes are strictly more specific than the user's existing
// 0.0.0.0/0, so Windows picks them automatically without us having to
// touch (and later restore) the real default route.
func (d *windowsDevice) installDefaultRoute(serverIP netip.Addr) error {
	if !serverIP.Is4() {
		return errors.New("l3client: default route requires an IPv4 server IP")
	}
	origGw, origLUID, err := windowsDefaultGateway(d.luid)
	if err != nil {
		return fmt.Errorf("l3client: discover default route: %w", err)
	}

	serverHost := netip.PrefixFrom(serverIP, 32)
	if err := origLUID.AddRoute(serverHost, origGw, winInterfaceMetric); err != nil &&
		!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("l3client: AddRoute server-host %s via %s: %w", serverIP, origGw, err)
	}
	d.underlayRoutes = append(d.underlayRoutes, underlayRoute{
		luid:    origLUID,
		dest:    serverHost,
		nextHop: origGw,
	})

	for _, r := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	} {
		if err := d.luid.AddRoute(r, netip.IPv4Unspecified(), winInterfaceMetric); err != nil &&
			!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			return fmt.Errorf("l3client: AddRoute default-half %s: %w", r, err)
		}
	}
	return nil
}

// windowsDefaultGateway walks the IPv4 forwarding table for the
// current default route, skipping any rows that belong to selfLUID so
// a stale /1 route from a previous crashed run does not get reused as
// the underlay default. We require the row's destination prefix to be
// length 0 (i.e. a real default route) and a non-unspecified
// next-hop, which together rule out point-to-point connected routes
// and link-local / loopback rows.
func windowsDefaultGateway(selfLUID winipcfg.LUID) (netip.Addr, winipcfg.LUID, error) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("GetIPForwardTable2: %w", err)
	}
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID == selfLUID {
			continue
		}
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		gw := r.NextHop.Addr()
		if !gw.IsValid() || gw.IsUnspecified() {
			continue
		}
		if !gw.Is4() {
			continue
		}
		return gw, r.InterfaceLUID, nil
	}
	return netip.Addr{}, 0, errors.New("no IPv4 default route found")
}

func (d *windowsDevice) Name() string { return d.name }

// Read returns exactly one IPv4 packet. wireguard/tun's wintun-backed
// Read can technically be called from a single goroutine only; we
// serialise here defensively so a misbehaving caller cannot corrupt the
// read scratch buffers.
func (d *windowsDevice) Read(p []byte) (int, error) {
	d.readBufMu.Lock()
	defer d.readBufMu.Unlock()
	d.readBufs[0] = d.readBufs[0][:cap(d.readBufs[0])]
	d.readSizes[0] = 0
	n, err := d.tun.Read(d.readBufs[:], d.readSizes[:], 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	sz := d.readSizes[0]
	if sz > len(p) {
		return 0, fmt.Errorf("l3client: packet length %d exceeds buffer %d", sz, len(p))
	}
	copy(p, d.readBufs[0][:sz])
	return sz, nil
}

// Write sends one IPv4 packet to wintun. wintun has no link-layer
// header offset, so we pass offset=0 and forward the caller's buffer
// directly without an intermediate copy — wintun copies internally
// into its send-ring slot.
func (d *windowsDevice) Write(p []byte) (int, error) {
	bufs := [1][]byte{p}
	if _, err := d.tun.Write(bufs[:], 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *windowsDevice) Close() error {
	// Best-effort: delete every route we installed on a foreign
	// underlay interface (currently just the /32 server-host route).
	// Errors are intentionally ignored — if the route was already
	// removed by the user or a Close from a previous run cleaned it
	// up, that is success from our perspective.
	for _, r := range d.underlayRoutes {
		_ = r.luid.DeleteRoute(r.dest, r.nextHop)
	}
	d.underlayRoutes = nil

	// Wipe everything on the TUN itself. FlushRoutes is scoped to our
	// own LUID so this cannot remove user-owned routes on other
	// interfaces, but it does drop the /1 halves and the connected
	// subnet route in one syscall pair.
	_ = d.luid.FlushRoutes(windows.AF_INET)
	_ = d.luid.FlushIPAddresses(windows.AF_INET)

	return d.tun.Close()
}

var _ Device = (*windowsDevice)(nil)
