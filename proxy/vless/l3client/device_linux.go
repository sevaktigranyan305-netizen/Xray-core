//go:build linux

package l3client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// linuxVnetHdrLen matches wireguard/tun's internal virtioNetHdrLen. The
// Read/Write API requires at least this many bytes of leading headroom
// in our buffers so the library can prepend/strip the virtio-net-hdr
// for GSO/GRO offload. We pick the maximum likely value (10 today) as a
// static constant; making it too large is harmless.
const linuxVnetHdrLen = 10

// linuxDevice is the Linux implementation of Device. It wraps
// wireguard/tun's multi-packet Read/Write API with a single-packet I/O
// surface and manages IP address + route assignment via netlink.
type linuxDevice struct {
	tun        wgtun.Device
	link       netlink.Link
	name       string
	mtu        int
	routes     []*netlink.Route // routes we installed; removed on Close
	addrs      []*netlink.Addr  // addresses we installed; removed on Close
	readBuf    [1][]byte
	readSizes  [1]int
	writeBufMu writerOnceBuffer
}

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
		name = "xray0"
	}

	tun, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("l3client: create tun %q: %w", name, err)
	}
	realName, err := tun.Name()
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: tun.Name: %w", err)
	}

	link, err := netlink.LinkByName(realName)
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: netlink.LinkByName %q: %w", realName, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: LinkSetMTU: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: LinkSetUp: %w", err)
	}

	d := &linuxDevice{
		tun:  tun,
		link: link,
		name: realName,
		mtu:  mtu,
	}
	d.readBuf[0] = make([]byte, linuxVnetHdrLen+mtu+128)

	ip4 := cfg.IP.As4()
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.IP(ip4[:]),
			Mask: net.CIDRMask(cfg.Subnet.Bits(), 32),
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, os.ErrExist) {
		_ = d.Close()
		return nil, fmt.Errorf("l3client: AddrAdd %s: %w", addr.IPNet, err)
	}
	d.addrs = append(d.addrs, addr)

	subnetRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst: &net.IPNet{
			IP:   cfg.Subnet.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(cfg.Subnet.Bits(), 32),
		},
	}
	if err := netlink.RouteReplace(subnetRoute); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("l3client: RouteReplace subnet %s: %w", cfg.Subnet, err)
	}
	d.routes = append(d.routes, subnetRoute)

	return d, nil
}

func (d *linuxDevice) Name() string { return d.name }

// Read returns exactly one IPv4 packet. wireguard/tun's batch API can
// return multiple packets in one call on Linux; we always pass a batch
// size of 1 so the library never aggregates more than a single packet
// into our buffer.
func (d *linuxDevice) Read(p []byte) (int, error) {
	d.readBuf[0] = d.readBuf[0][:cap(d.readBuf[0])]
	d.readSizes[0] = 0
	n, err := d.tun.Read(d.readBuf[:], d.readSizes[:], linuxVnetHdrLen)
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
	copy(p, d.readBuf[0][linuxVnetHdrLen:linuxVnetHdrLen+sz])
	return sz, nil
}

// Write sends one IPv4 packet to the kernel. We copy the packet into a
// scratch buffer that reserves linuxVnetHdrLen bytes of leading headroom
// so wireguard/tun can populate its virtio-net-hdr in-place.
func (d *linuxDevice) Write(p []byte) (int, error) {
	need := linuxVnetHdrLen + len(p)
	if cap(d.writeBufMu.buf) < need {
		d.writeBufMu.buf = make([]byte, need)
	} else {
		d.writeBufMu.buf = d.writeBufMu.buf[:need]
	}
	copy(d.writeBufMu.buf[linuxVnetHdrLen:], p)
	bufs := [1][]byte{d.writeBufMu.buf}
	_, err := d.tun.Write(bufs[:], linuxVnetHdrLen)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *linuxDevice) Close() error {
	for _, r := range d.routes {
		_ = netlink.RouteDel(r)
	}
	d.routes = nil
	for _, a := range d.addrs {
		_ = netlink.AddrDel(d.link, a)
	}
	d.addrs = nil
	return d.tun.Close()
}

var _ Device = (*linuxDevice)(nil)

// _ silences unused-import warnings if netip goes unused during partial
// implementations; netip is referenced by deviceConfig which is what
// newDevice consumes.
var _ = netip.Addr{}
