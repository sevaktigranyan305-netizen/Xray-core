//go:build android

package l3client

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// androidVnetHdrLen mirrors device_linux.go's linuxVnetHdrLen. wireguard/tun
// on android uses the same Linux backend (virtio-net-hdr GSO/GRO offload),
// so Read/Write require the same 10-byte leading headroom in our buffers.
const androidVnetHdrLen = 10

// androidDevice is the Android implementation of Device. Unlike the Linux
// desktop backend we do NOT open /dev/net/tun ourselves: on Android the GUI
// (e.g. v2rayNG's V2RayVpnService) calls VpnService.Builder.establish() to
// get a kernel TUN file descriptor and then passes that fd to xray-core via
// the xray.tun.fd / XRAY_TUN_FD environment variable (the same channel the
// upstream proxy/tun inbound already uses). We adopt that fd, hand it to
// wireguard/tun's CreateUnmonitoredTUNFromFD, and let the rest of l3client
// drive packet I/O. Address assignment, routing and MTU are configured by
// VpnService.Builder on the Java side; the Go side never tries to talk to
// netlink (we have no CAP_NET_ADMIN inside the app sandbox anyway).
type androidDevice struct {
	tun        wgtun.Device
	name       string
	mtu        int
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

	fdStr := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })
	if fdStr == "" {
		return nil, fmt.Errorf("l3client: %s env not set; on android the host application must establish a VpnService TUN and pass the fd via this environment variable", platform.TunFdKey)
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil || fd <= 0 {
		return nil, fmt.Errorf("l3client: invalid %s value %q", platform.TunFdKey, fdStr)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("l3client: SetNonblock(%d): %w", fd, err)
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = MTU
	}

	tun, name, err := wgtun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return nil, fmt.Errorf("l3client: CreateUnmonitoredTUNFromFD(%d): %w", fd, err)
	}

	d := &androidDevice{
		tun:  tun,
		name: name,
		mtu:  mtu,
	}
	d.readBuf[0] = make([]byte, androidVnetHdrLen+mtu+128)
	return d, nil
}

func (d *androidDevice) Name() string { return d.name }

// Read returns exactly one IPv4 packet. wireguard/tun's batch API can
// return multiple packets in one call on Linux/Android; we always pass a
// batch size of 1 so the library never aggregates more than a single
// packet into our buffer.
func (d *androidDevice) Read(p []byte) (int, error) {
	d.readBuf[0] = d.readBuf[0][:cap(d.readBuf[0])]
	d.readSizes[0] = 0
	n, err := d.tun.Read(d.readBuf[:], d.readSizes[:], androidVnetHdrLen)
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
	copy(p, d.readBuf[0][androidVnetHdrLen:androidVnetHdrLen+sz])
	return sz, nil
}

// Write sends one IPv4 packet to the kernel. We copy the packet into a
// scratch buffer that reserves androidVnetHdrLen bytes of leading headroom
// so wireguard/tun can populate its virtio-net-hdr in-place.
func (d *androidDevice) Write(p []byte) (int, error) {
	need := androidVnetHdrLen + len(p)
	if cap(d.writeBufMu.buf) < need {
		d.writeBufMu.buf = make([]byte, need)
	} else {
		d.writeBufMu.buf = d.writeBufMu.buf[:need]
	}
	copy(d.writeBufMu.buf[androidVnetHdrLen:], p)
	bufs := [1][]byte{d.writeBufMu.buf}
	_, err := d.tun.Write(bufs[:], androidVnetHdrLen)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close drops the wireguard/tun wrapper. The underlying VpnService fd is
// owned by the Java side: revoke()/stopSelf() on the VpnService closes the
// kernel TUN, which makes our outstanding Read return io.EOF and the
// l3client retry loop reconnect cleanly. We deliberately do NOT close the
// raw fd ourselves to avoid double-close races with VpnService.
func (d *androidDevice) Close() error {
	return d.tun.Close()
}

var _ Device = (*androidDevice)(nil)

// _ silences unused-import warnings if netip goes unused during partial
// implementations; netip is referenced by deviceConfig which is what
// newDevice consumes.
var _ = netip.Addr{}
