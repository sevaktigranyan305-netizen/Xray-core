package virtualnet

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
)

// Endpoint represents one VLESS user's presence on the virtual network.
// The user is anchored to a single virtual IPv4 address. The stream is the
// user's VLESS TCP-like channel, carrying length-prefixed IPv4 packets as
// defined in packet.go.
//
// Endpoints are owned by a *Switch: callers get them back from
// Switch.Register and must call Close (or let the switch close them on
// shutdown) when the user disconnects.
type Endpoint struct {
	// IP is the virtual IP assigned to this user; it is also the key in
	// the switch's routing table.
	IP netip.Addr

	// UUID is an opaque identifier the switch uses only for logging. It
	// is typically the VLESS user UUID string.
	UUID string

	// stream is the user's VLESS connection; both directions flow
	// over this single connection, framed by writeFrame/readFrame.
	stream io.ReadWriteCloser

	// sw is the switch that owns this endpoint. It is set by
	// Switch.Register and is used by the packet-reading loop to inject
	// packets into the switch's routing fast path.
	sw *Switch

	// writeMu serialises frame writes so that length prefixes and their
	// payloads are never interleaved by concurrent goroutines. The
	// switch calls Send from at least two goroutines per endpoint (the
	// gVisor outbound reader, plus peer-to-peer forwards).
	writeMu sync.Mutex

	// closeOnce guarantees that the shutdown side-effects (removal from
	// the switch, context cancel, stream close) only run once even if
	// multiple goroutines race on Close.
	closeOnce sync.Once

	// ctx/cancel let the read loop notice when the switch or user asks
	// for shutdown. The context is derived from the switch's context.
	ctx    context.Context
	cancel context.CancelFunc

	// done is closed when the read loop has returned. Consumers
	// (notably the VLESS inbound Process goroutine) block on Wait() to
	// keep the VLESS connection open for the lifetime of the endpoint.
	done chan struct{}
}

// ErrEndpointClosed is returned by Send after the endpoint has been closed
// or the underlying stream errored.
var ErrEndpointClosed = errors.New("virtualnet: endpoint is closed")

// Send writes a single IPv4 packet to the user's stream. It is safe to
// call from multiple goroutines; writes are serialised.
func (e *Endpoint) Send(pkt []byte) error {
	select {
	case <-e.ctx.Done():
		return ErrEndpointClosed
	default:
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	return writeFrame(e.stream, pkt)
}

// Wait blocks until the endpoint's packet reader exits (user disconnected
// or switch shut down). The VLESS inbound handler blocks on this so that
// the underlying connection is not torn down early.
func (e *Endpoint) Wait() {
	<-e.done
}

// Close shuts down the endpoint: removes it from the switch, cancels the
// read loop, and closes the underlying stream. It is idempotent.
func (e *Endpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.cancel()
		if e.sw != nil {
			e.sw.unregister(e.IP, e)
		}
		if e.stream != nil {
			err = e.stream.Close()
		}
	})
	return err
}

// run is the endpoint's read loop: reads framed IPv4 packets from the
// user's stream and hands each one to the switch for forwarding. It
// returns when the stream is closed, the context is cancelled, or an
// unrecoverable framing error is encountered. Caller is expected to
// dispatch this as a goroutine via Switch.Register.
func (e *Endpoint) run() {
	defer close(e.done)
	defer func() {
		// Ensure cleanup even on panic inside the read loop.
		_ = e.Close()
	}()

	for {
		if e.ctx.Err() != nil {
			return
		}
		pkt, err := readFrame(e.stream)
		if err != nil {
			return
		}
		if pkt == nil {
			// Keep-alive frame; loop again.
			continue
		}
		// Hand off to the switch. The switch never blocks on a single
		// endpoint for long — it drops undeliverable packets and moves
		// on, which is the behaviour of a real L3 forwarder.
		e.sw.forward(e, pkt)
	}
}
