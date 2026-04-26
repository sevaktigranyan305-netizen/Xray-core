// Package virtualnet implements an L3 virtual network that multiplexes
// authenticated VLESS users onto a shared IPv4 subnet (default 10.0.0.0/24).
//
// Design assumptions (documented here so the whole package is clear):
//
//   - A VLESS stream carries raw IPv4 packets, length-prefixed with a 2-byte
//     big-endian frame header. This is the minimum framing needed to
//     reconstruct packet boundaries over a reliable byte stream (TCP-like
//     VLESS transport).
//
//   - The server is the implicit gateway at subnet.IP+1 (e.g. 10.0.0.1). It
//     reuses the existing gVisor userspace stack (proxy/wireguard/gvisortun)
//     to terminate traffic destined to non-user IPs — this gives us TCP/UDP
//     sockets that can be plugged into xray's routing.Dispatcher for
//     per-user outbound routing rules.
//
//   - Direct user-to-user traffic (e.g. 10.0.0.2 -> 10.0.0.3) is forwarded
//     at L3 entirely inside this process: packets are matched against the
//     endpoint table by destination IP and written to the peer's stream
//     without touching any outbound. This is the "L3 switch" the task
//     requires.
//
//   - Only IPv4 is supported in the default subnet. IPv6 would require a
//     parallel code path; the subnet type already permits it but the
//     forwarding fast-path only inspects IPv4 headers.
package virtualnet

import (
	"encoding/binary"
	"errors"
	"io"
)

// MaxPacketSize is the maximum inner IPv4 packet size we accept on the
// virtual link. 1500 covers standard Ethernet MTU; we give a bit of slack
// for any upstream framing and reject anything larger to bound memory.
const MaxPacketSize = 1600

// frameHeaderSize is the number of bytes in the length prefix that precedes
// each IPv4 packet on the VLESS stream.
const frameHeaderSize = 2

// ErrFrameTooLarge is returned when the length-prefixed frame exceeds
// MaxPacketSize. A well-behaved client will never produce this.
var ErrFrameTooLarge = errors.New("virtualnet: framed packet exceeds MaxPacketSize")

// readFrame reads one length-prefixed IPv4 packet from r into a fresh
// buffer. It returns io.EOF when the underlying stream is closed cleanly
// between frames.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		// Empty frame — treated as a keep-alive. Skip and let the caller
		// loop again.
		return nil, nil
	}
	if n > MaxPacketSize {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeFrame writes a length-prefixed IPv4 packet to w. The call is
// atomic from the perspective of concurrent writers only if the caller
// serialises access; Endpoint.Send serialises per-endpoint.
func writeFrame(w io.Writer, pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if len(pkt) > MaxPacketSize {
		return ErrFrameTooLarge
	}
	// Single Write call via a stack-allocated scratch buffer to avoid a
	// short write leaving the stream in a half-framed state.
	var scratch [frameHeaderSize + MaxPacketSize]byte
	binary.BigEndian.PutUint16(scratch[:frameHeaderSize], uint16(len(pkt)))
	copy(scratch[frameHeaderSize:], pkt)
	_, err := w.Write(scratch[:frameHeaderSize+len(pkt)])
	return err
}

// ipv4Header is a minimal view over the bytes of an IPv4 packet. We only
// need version + src + dst to drive routing, so we avoid a full parser.
type ipv4Header struct {
	version byte
	src     [4]byte
	dst     [4]byte
}

// parseIPv4Header returns the source and destination address of an IPv4
// packet. It returns ok=false for non-IPv4 or truncated packets; those are
// dropped silently by the switch (same behaviour as a real L3 switch).
func parseIPv4Header(pkt []byte) (ipv4Header, bool) {
	if len(pkt) < 20 {
		return ipv4Header{}, false
	}
	h := ipv4Header{version: pkt[0] >> 4}
	if h.version != 4 {
		return ipv4Header{}, false
	}
	copy(h.src[:], pkt[12:16])
	copy(h.dst[:], pkt[16:20])
	return h, true
}
