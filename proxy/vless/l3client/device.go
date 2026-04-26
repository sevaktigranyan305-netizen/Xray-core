// Package l3client implements the client side of the VLESS L3 virtual
// network. It dials the VLESS server, reads the 4-byte assigned-IP
// preamble written by proxy/vless/virtualnet, creates a real system TUN
// interface, assigns the IP, installs routes, and then bridges raw IPv4
// packets between the TUN and the length-prefixed VLESS stream.
//
// The package has three logical layers:
//
//   - Device: a minimal single-packet Read/Write abstraction over
//     golang.zx2c4.com/wireguard/tun. Platform-specific configuration
//     (address assignment, routing, MTU) lives in device_<os>.go behind
//     build tags.
//
//   - Client: the VLESS-agnostic tunnel driver. Given any
//     io.ReadWriteCloser that speaks the virtualnet framing on top, it
//     reads the preamble, brings up the Device, and runs both halves of
//     the TUN<->stream packet loop.
//
//   - Integration in proxy/vless/outbound/outbound.go: when an outbound
//     config has virtualNetwork.enabled=true, a single self-bootstrapping
//     goroutine dials the server through the standard outbound stack,
//     passes the post-handshake stream into a Client, and retries on
//     disconnect with exponential backoff.
package l3client

import (
	"net/netip"
)

// MTU is the default MTU used on the TUN interface. 1420 leaves headroom
// for TLS/REALITY + TCP overhead on a 1500 byte path MTU, matching what
// WireGuard chooses for the same reason.
const MTU = 1420

// Device is a minimal single-packet TUN handle. It exists so the rest of
// the package never has to know about wireguard/tun's multi-packet
// batched API, virtio-net-hdr offsets, or platform-specific address
// management.
//
// Implementations are created by newDevice (platform-specific) after the
// client has learned its assigned virtual IP from the server.
type Device interface {
	// Read blocks until at least one packet is available and copies
	// exactly one IPv4 packet into p. Returns the number of bytes
	// written into p. An error indicates the device has been closed.
	Read(p []byte) (int, error)

	// Write sends one IPv4 packet to the kernel. Short writes are not
	// returned — either the full packet is accepted or an error.
	Write(p []byte) (int, error)

	// Name returns the kernel-visible interface name (e.g. "utun3" on
	// darwin, "xray0" on linux).
	Name() string

	// Close brings the interface down and releases the file
	// descriptor. Any in-flight Read/Write returns an error.
	Close() error
}

// writerOnceBuffer is a tiny per-device scratch area for Write's headroom
// allocation, shared by the linux and darwin device backends. Access is
// serialised by single-threaded use in the client's writeLoop; if that
// ever changes a sync.Mutex should be added here.
type writerOnceBuffer struct {
	buf []byte
}

// deviceConfig is the set of parameters every platform-specific newDevice
// needs. The subnet is passed so the /prefix can be placed on the
// interface (ip addr add <ip>/<prefixlen>), and so routes can be installed
// for the intra-tunnel subnet.
type deviceConfig struct {
	// Name is the requested kernel interface name. Empty means let the
	// platform choose (notably required on darwin, where utunN is kernel-
	// assigned).
	Name string

	// IP is the virtual IPv4 address the server assigned to us. It is
	// assigned to the TUN with the subnet's prefix length.
	IP netip.Addr

	// Subnet is the virtual network the server is announcing (e.g.
	// 10.0.0.0/24). Used both for the address assignment's prefix length
	// and for the intra-tunnel route.
	Subnet netip.Prefix

	// MTU is the interface MTU. 0 means use the package default.
	MTU int

	// ServerIP, if set, is the real IPv4 of the VLESS server. It is
	// used only when DefaultRoute is true, to install a /32 host route
	// for the server via the underlay gateway (so packets toward the
	// server keep using the host's original route instead of being
	// reflected through the TUN).
	ServerIP netip.Addr

	// DefaultRoute, when true, installs 0.0.0.0/0 through the TUN
	// interface (as two /1 routes to avoid disturbing the underlying
	// real default route). When false, only the intra-tunnel subnet
	// route is installed.
	DefaultRoute bool
}
