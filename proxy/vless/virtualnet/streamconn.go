package virtualnet

import (
	"errors"
	"io"

	"github.com/xtls/xray-core/common/buf"
)

// StreamConn wraps an xray buf.Reader / buf.Writer pair into an
// io.ReadWriteCloser suitable for feeding the Switch. The VLESS inbound
// uses this because after the VLESS handshake the useful body channel is
// exposed as a pair of MultiBuffer-oriented streams rather than a raw
// net.Conn.
//
// Read pulls from the buf.Reader and splices the resulting MultiBuffer
// into the caller's byte slice. Because individual IPv4 packets are very
// rarely larger than the MultiBuffer chunk size, we cache the leftover
// bytes of a read and drain them on subsequent calls; this keeps the
// IP-framing code in packet.go oblivious to MultiBuffer boundaries.
//
// Write wraps the caller's bytes in a single buf.Buffer and forwards via
// WriteMultiBuffer, taking care to return ErrShortWrite when the buffer
// size is exceeded (frame writer never does this because it caps at
// MaxPacketSize, but we guard defensively).
type StreamConn struct {
	r buf.Reader
	w buf.Writer

	// leftover holds any bytes from the most recent ReadMultiBuffer
	// that didn't fit in the caller's slice on the previous Read.
	leftover []byte

	// closer closes the underlying transport (the VLESS TCP connection).
	closer io.Closer
}

// NewStreamConn builds a StreamConn around an xray buf.Reader/Writer
// pair. closer is called from Close() — it should tear down the
// underlying VLESS connection so both halves unblock.
func NewStreamConn(r buf.Reader, w buf.Writer, closer io.Closer) *StreamConn {
	return &StreamConn{r: r, w: w, closer: closer}
}

// Read implements io.Reader.
func (c *StreamConn) Read(p []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		if len(c.leftover) == 0 {
			c.leftover = nil
		}
		return n, nil
	}
	mb, err := c.r.ReadMultiBuffer()
	if err != nil {
		return 0, err
	}
	if mb.IsEmpty() {
		// Empty MultiBuffer is effectively a no-op; return 0 and let
		// the caller loop. io.EOF is never spurious here because
		// ReadMultiBuffer returns a real error on stream close.
		buf.ReleaseMulti(mb)
		return 0, nil
	}
	// Flatten the MultiBuffer into a contiguous byte slice, then hand
	// out as much as the caller asked for and keep the rest as
	// leftover.
	var flat []byte
	for _, b := range mb {
		flat = append(flat, b.Bytes()...)
	}
	buf.ReleaseMulti(mb)
	n := copy(p, flat)
	if n < len(flat) {
		c.leftover = flat[n:]
	}
	return n, nil
}

// ErrShortWrite is returned by Write if the caller's buffer exceeds the
// buf package's single-buffer capacity. The framing in packet.go enforces
// a much smaller cap (MaxPacketSize) so this is a defensive guard only.
var ErrShortWrite = errors.New("virtualnet: write exceeds buf.Size")

// Write implements io.Writer.
func (c *StreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b := buf.New()
	// buf.Buffer.Write may return ErrOverflow on oversize. If it does
	// we fall back to returning ErrShortWrite — callers shouldn't feed
	// oversize buffers here in the first place.
	written, err := b.Write(p)
	if err != nil {
		b.Release()
		return 0, ErrShortWrite
	}
	if written < len(p) {
		b.Release()
		return 0, ErrShortWrite
	}
	if err := c.w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		return 0, err
	}
	return written, nil
}

// Close implements io.Closer.
func (c *StreamConn) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}
