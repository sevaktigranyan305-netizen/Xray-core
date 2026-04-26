//go:build darwin

package l3client

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// darwinDevice is the macOS implementation of Device. It wraps
// wireguard/tun's utun-based device and shells out to /sbin/ifconfig and
// /sbin/route for address and route management — macOS has no libnetlink
// equivalent and its ioctl interfaces for these tasks are historically
// brittle, so the system tools are the least-surprising path.
type darwinDevice struct {
	tun        wgtun.Device
	name       string
	mtu        int
	subnet     netip.Prefix
	ip         netip.Addr
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

	// macOS utun devices are always named utunN; passing "" lets the
	// kernel pick the lowest free index. We ignore cfg.Name entirely
	// rather than silently rejecting conflicting user choices, because
	// the user-visible name is irrelevant for our use case.
	tun, err := wgtun.CreateTUN("", mtu)
	if err != nil {
		return nil, fmt.Errorf("l3client: create tun: %w", err)
	}
	realName, err := tun.Name()
	if err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: tun.Name: %w", err)
	}

	d := &darwinDevice{
		tun:    tun,
		name:   realName,
		mtu:    mtu,
		subnet: cfg.Subnet,
		ip:     cfg.IP,
	}
	// Darwin wireguard/tun does not use virtio-net-hdr, so read buffers
	// need no leading headroom. We still reserve a small fixed slack
	// above the MTU to be defensive against oversized packets.
	d.readBuf[0] = make([]byte, mtu+128)

	gateway := gatewayOf(cfg.Subnet)
	ifconfigArgs := []string{
		realName, "inet",
		cfg.IP.String(), gateway.String(),
		"netmask", maskOf(cfg.Subnet),
		"mtu", fmt.Sprintf("%d", mtu),
		"up",
	}
	if out, err := exec.Command("/sbin/ifconfig", ifconfigArgs...).CombinedOutput(); err != nil {
		_ = tun.Close()
		return nil, fmt.Errorf("l3client: ifconfig %v: %w: %s", ifconfigArgs, err, string(out))
	}

	routeArgs := []string{"-q", "add", "-net", cfg.Subnet.String(), "-interface", realName}
	// We tolerate route-add errors here: a stale route from a crashed
	// previous run is fine; it points at the same interface name
	// namespace and gets cleaned up by the kernel when the utun device
	// closes. We do not bubble the failure up because ifconfig+the
	// interface route implicit from inet assignment are usually enough
	// to reach peers on the subnet.
	_, _ = exec.Command("/sbin/route", routeArgs...).CombinedOutput()

	return d, nil
}

func (d *darwinDevice) Name() string { return d.name }

func (d *darwinDevice) Read(p []byte) (int, error) {
	d.readBuf[0] = d.readBuf[0][:cap(d.readBuf[0])]
	d.readSizes[0] = 0
	n, err := d.tun.Read(d.readBuf[:], d.readSizes[:], 0)
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
	copy(p, d.readBuf[0][:sz])
	return sz, nil
}

func (d *darwinDevice) Write(p []byte) (int, error) {
	if cap(d.writeBufMu.buf) < len(p) {
		d.writeBufMu.buf = make([]byte, len(p))
	} else {
		d.writeBufMu.buf = d.writeBufMu.buf[:len(p)]
	}
	copy(d.writeBufMu.buf, p)
	bufs := [1][]byte{d.writeBufMu.buf}
	_, err := d.tun.Write(bufs[:], 0)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *darwinDevice) Close() error {
	// Deleting the utun interface implicitly removes associated routes
	// and addresses on Darwin, so we do not call route/ifconfig here.
	return d.tun.Close()
}

// gatewayOf returns subnet.Addr()+1, which is our fixed server-gateway
// convention (e.g. 10.0.0.1 for 10.0.0.0/24). It mirrors virtualnet's
// server-side calculation in Switch configuration.
func gatewayOf(p netip.Prefix) netip.Addr {
	return p.Masked().Addr().Next()
}

// maskOf converts a /N prefix to dotted-decimal netmask form that
// /sbin/ifconfig understands on Darwin.
func maskOf(p netip.Prefix) string {
	bits := p.Bits()
	if bits < 0 {
		bits = 0
	}
	if bits > 32 {
		bits = 32
	}
	var m uint32
	if bits == 0 {
		m = 0
	} else {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

var _ Device = (*darwinDevice)(nil)
