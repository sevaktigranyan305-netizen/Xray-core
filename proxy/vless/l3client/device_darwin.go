//go:build darwin

package l3client

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// darwinAFHdrLen is the 4-byte address-family prefix that
// wireguard/tun's darwin backend prepends to every utun frame
// (PF_INET = 0x02). wgtun.NativeTun.Read does
// `bufs[0][offset-4:]` and panics if offset<4; Write rejects
// offset<4 with io.ErrShortBuffer. We pass exactly 4 and reserve
// the same amount of leading headroom in our read/write buffers.
const darwinAFHdrLen = 4

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

	// cleanupRoutes holds the dotted-decimal destinations of every
	// route we added through /sbin/route. Close() walks this slice in
	// reverse, running `route delete` for each, so the host's route
	// table is restored even if the tunnel crashed mid-setup.
	cleanupRoutes []string
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

	// macOS utun devices are always named utunN. wireguard/tun's
	// CreateTUN requires the literal string "utun" to make the kernel
	// pick the lowest free index; passing "" (or anything else that
	// doesn't match "utun%d") fails its name-parse with
	// `Interface name must be utun[0-9]*`. We ignore cfg.Name entirely
	// rather than silently rejecting conflicting user choices, because
	// the user-visible name is irrelevant for our use case.
	tun, err := wgtun.CreateTUN("utun", mtu)
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
	// Darwin wireguard/tun prepends a 4-byte address-family header
	// (PF_INET) on every utun frame, so the read buffer must reserve
	// darwinAFHdrLen of leading headroom in addition to the MTU. The
	// extra 128 is defensive slack against oversized packets.
	d.readBuf[0] = make([]byte, darwinAFHdrLen+mtu+128)

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
	if _, err := exec.Command("/sbin/route", routeArgs...).CombinedOutput(); err == nil {
		d.cleanupRoutes = append(d.cleanupRoutes, cfg.Subnet.String())
	}

	if cfg.DefaultRoute {
		if err := d.installDefaultRoute(cfg.ServerIP, realName); err != nil {
			_ = d.Close()
			return nil, err
		}
	}

	return d, nil
}

// installDefaultRoute hijacks the macOS default route through the utun
// using the same /1+/1 trick as the Linux backend. macOS has no
// per-route priority we can rely on, so we add 0/1 and 128/1 through
// the utun, and a /32 host route for the VLESS server via the
// pre-existing default gateway to avoid a loop. All added routes are
// recorded on the device so Close() can delete them.
func (d *darwinDevice) installDefaultRoute(serverIP netip.Addr, realName string) error {
	if !serverIP.Is4() {
		return errors.New("l3client: default route requires an IPv4 server IP")
	}
	origGw, err := darwinDefaultGateway()
	if err != nil {
		return fmt.Errorf("l3client: discover default route: %w", err)
	}

	if out, err := exec.Command("/sbin/route", "-q", "add", "-host", serverIP.String(), origGw.String()).CombinedOutput(); err != nil {
		return fmt.Errorf("l3client: route add -host %s %s: %w: %s", serverIP, origGw, err, string(out))
	}
	d.cleanupRoutes = append(d.cleanupRoutes, serverIP.String())

	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if out, err := exec.Command("/sbin/route", "-q", "add", "-net", dst, "-interface", realName).CombinedOutput(); err != nil {
			return fmt.Errorf("l3client: route add -net %s: %w: %s", dst, err, string(out))
		}
		d.cleanupRoutes = append(d.cleanupRoutes, dst)
	}
	return nil
}

// darwinDefaultGateway parses `/sbin/route -n get default` to find the
// current IPv4 default gateway. We parse text rather than call into
// sysctl because the textual output is extremely stable across macOS
// versions and keeps the package free of a darwin-only sysctl
// dependency.
func darwinDefaultGateway() (netip.Addr, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		a, err := netip.ParseAddr(fields[1])
		if err != nil {
			return netip.Addr{}, err
		}
		if !a.Is4() {
			return netip.Addr{}, errors.New("default gateway is not IPv4")
		}
		return a, nil
	}
	return netip.Addr{}, errors.New("no default gateway reported by /sbin/route")
}

func (d *darwinDevice) Name() string { return d.name }

func (d *darwinDevice) Read(p []byte) (int, error) {
	d.readBuf[0] = d.readBuf[0][:cap(d.readBuf[0])]
	d.readSizes[0] = 0
	n, err := d.tun.Read(d.readBuf[:], d.readSizes[:], darwinAFHdrLen)
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
	copy(p, d.readBuf[0][darwinAFHdrLen:darwinAFHdrLen+sz])
	return sz, nil
}

func (d *darwinDevice) Write(p []byte) (int, error) {
	need := darwinAFHdrLen + len(p)
	if cap(d.writeBufMu.buf) < need {
		d.writeBufMu.buf = make([]byte, need)
	} else {
		d.writeBufMu.buf = d.writeBufMu.buf[:need]
	}
	copy(d.writeBufMu.buf[darwinAFHdrLen:], p)
	bufs := [1][]byte{d.writeBufMu.buf}
	_, err := d.tun.Write(bufs[:], darwinAFHdrLen)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *darwinDevice) Close() error {
	// Remove routes we installed, newest first. /sbin/route delete is
	// safe to call on already-absent routes (returns an error we
	// intentionally ignore), so duplicate Close() calls don't harm
	// anything.
	for i := len(d.cleanupRoutes) - 1; i >= 0; i-- {
		_, _ = exec.Command("/sbin/route", "-q", "delete", d.cleanupRoutes[i]).CombinedOutput()
	}
	d.cleanupRoutes = nil
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
