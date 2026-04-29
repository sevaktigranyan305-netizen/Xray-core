package l3client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/xtls/xray-core/proxy/vless/virtualnet"
)

// Client drives one VLESS L3 tunnel: it reads the 4-byte assigned-IP
// preamble from the server, brings up a Device with that IP and the
// configured subnet, and then spawns two goroutines bridging packets in
// each direction between the Device and the VLESS stream.
//
// Client is a short-lived object created per-connection. Run blocks for
// the lifetime of the tunnel and returns once either side has
// disconnected; the caller is expected to handle reconnect logic.
type Client struct {
	cfg Config
}

// Config is the set of client-side knobs surfaced from the outbound
// config. Zero values default to sensible production values.
type Config struct {
	// Subnet is the virtual network subnet the server announced via
	// JSON config (e.g. 10.0.0.0/24). The client uses it both to
	// compute the interface's prefix length and to install a route for
	// peer-to-peer traffic.
	Subnet netip.Prefix

	// InterfaceName is the preferred kernel interface name. On Linux
	// empty means "xray0"; on Darwin the value is ignored because utun
	// interfaces are kernel-named.
	InterfaceName string

	// MTU overrides the default interface MTU (see the package-level
	// MTU constant). Most deployments should leave this at 0.
	MTU int

	// DefaultRoute, when true, installs 0.0.0.0/0 (as two /1 routes to
	// avoid deleting the real default) through the TUN. The server's
	// real IP must be excluded via the underlay gateway, so Run needs
	// the resolved serverIP to install a /32 exclusion. When false,
	// only the intra-tunnel subnet is routed through the TUN.
	DefaultRoute bool

	// AssignedIP, when set, is the virtual IPv4 the panel pre-allocated
	// for this user via the server-side IPAM. When provided the client
	// uses it as the authoritative TUN address and validates that the
	// server's preamble announces the same value, returning a loud
	// error on mismatch instead of silently mis-routing traffic.
	//
	// When unset (zero Addr) the client falls back to the legacy
	// behaviour of trusting whatever IP the server preamble announces.
	// Linux/darwin clients can run either way; android clients must
	// always set this field because the host process configures the
	// TUN interface address before xray ever sees the file descriptor
	// and there is no other channel to keep the two views consistent.
	AssignedIP netip.Addr
}

// ActivityUpdater is the subset of common/signal.ActivityTimer we need.
// Using an interface instead of importing signal keeps this package free
// of xray-specific deps so it can be unit-tested in isolation.
type ActivityUpdater interface {
	Update()
}

// NewClient constructs a Client with the provided configuration. It does
// not allocate any OS resources until Run is called.
func NewClient(cfg Config) (*Client, error) {
	if !cfg.Subnet.IsValid() {
		return nil, errors.New("l3client: Subnet must be set")
	}
	if !cfg.Subnet.Addr().Is4() {
		return nil, errors.New("l3client: Subnet must be IPv4")
	}
	if cfg.AssignedIP.IsValid() {
		if !cfg.AssignedIP.Is4() {
			return nil, errors.New("l3client: AssignedIP must be IPv4")
		}
		if !cfg.Subnet.Contains(cfg.AssignedIP) {
			return nil, fmt.Errorf("l3client: AssignedIP %s is outside subnet %s", cfg.AssignedIP, cfg.Subnet)
		}
	}
	return &Client{cfg: cfg}, nil
}

// Run blocks running the tunnel: it reads the preamble from stream,
// creates the TUN device, and shuttles packets between the two until
// either the context is cancelled or one end returns an error.
//
// stream is consumed as an already-established VLESS byte stream with
// virtualnet framing: the first PreambleSize bytes are the server's
// IP announcement, everything after is length-prefixed IPv4 frames.
// The caller is responsible for closing stream; Run closes the TUN
// device it creates.
func (c *Client) Run(ctx context.Context, stream io.ReadWriteCloser, activity ActivityUpdater, serverIP netip.Addr) error {
	ip4, err := virtualnet.ReadIPPreamble(stream)
	if err != nil {
		return fmt.Errorf("l3client: read ip preamble: %w", err)
	}
	ip := netip.AddrFrom4(ip4)
	if !c.cfg.Subnet.Contains(ip) {
		return fmt.Errorf("l3client: server announced %s outside subnet %s", ip, c.cfg.Subnet)
	}
	// When the panel has pre-allocated an IP for this user via the
	// server-side IPAM and embedded it into the VLESS link as
	// vnetIp=…, the host process (e.g. v2rayNG via VpnService.Builder)
	// has already configured the TUN with that address before xray
	// ever sees the file descriptor. Honour the same source of truth
	// here: refuse to bring the tunnel up if the server announces a
	// different address, since silently using two different IPs would
	// look like working VPN with all packets dropped on the server's
	// anti-spoofing check.
	if c.cfg.AssignedIP.IsValid() && c.cfg.AssignedIP != ip {
		return fmt.Errorf("l3client: server announced %s but link declares vnetIp=%s; ask the panel admin to regenerate the VLESS link so the IPs match", ip, c.cfg.AssignedIP)
	}

	// The device layer uses serverIP to install a /32 host-route
	// exclusion through the underlay gateway so that packets toward
	// the VLESS server keep using the original route instead of being
	// reflected back through the TUN. Unknown (zero) means "don't
	// install a default route at all" — keeps backwards-compat for
	// callers who only want the intra-tunnel subnet.
	dev, err := newDevice(deviceConfig{
		Name:         c.cfg.InterfaceName,
		IP:           ip,
		Subnet:       c.cfg.Subnet,
		MTU:          c.cfg.MTU,
		ServerIP:     serverIP,
		DefaultRoute: c.cfg.DefaultRoute,
	})
	if err != nil {
		return err
	}
	defer dev.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	var firstErr error
	var errMu sync.Mutex
	record := func(err error) {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	go func() {
		defer wg.Done()
		defer cancel()
		record(tunToStream(runCtx, dev, stream, activity))
	}()
	go func() {
		defer wg.Done()
		defer cancel()
		record(streamToTun(runCtx, stream, dev, activity))
	}()

	wg.Wait()
	// streamToTun will unblock via the stream Close triggered by the
	// first goroutine to exit; tunToStream unblocks via dev.Close in
	// the defer above. Either way we've raced cancel correctly.
	return firstErr
}

// tunToStream reads packets from the TUN device and writes them as
// virtualnet-framed IPv4 packets to the VLESS stream. It returns when
// the context is cancelled, the device is closed, or a write fails.
func tunToStream(ctx context.Context, dev Device, stream io.Writer, activity ActivityUpdater) error {
	buf := make([]byte, virtualnet.MaxPacketSize)
	frame := make([]byte, 2+virtualnet.MaxPacketSize)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := dev.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		if n == 0 {
			continue
		}
		if n > virtualnet.MaxPacketSize {
			continue
		}
		frame[0] = byte(n >> 8)
		frame[1] = byte(n)
		copy(frame[2:], buf[:n])
		if _, err := stream.Write(frame[:2+n]); err != nil {
			return fmt.Errorf("stream write: %w", err)
		}
		if activity != nil {
			activity.Update()
		}
	}
}

// streamToTun reads virtualnet-framed IPv4 packets from the VLESS stream
// and injects them into the TUN device. It returns when the context is
// cancelled or a read/write fails.
func streamToTun(ctx context.Context, stream io.Reader, dev Device, activity ActivityUpdater) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pkt, err := readFrameWrapper(stream)
		if err != nil {
			return fmt.Errorf("stream read: %w", err)
		}
		if len(pkt) == 0 {
			continue
		}
		if _, err := dev.Write(pkt); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
		if activity != nil {
			activity.Update()
		}
	}
}

// readFrameWrapper wraps virtualnet.ReadFrame but with unexported access
// — virtualnet's readFrame is package-private, so we replicate the same
// trivial protocol here rather than widening its API surface.
func readFrameWrapper(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 {
		return nil, nil
	}
	if n > virtualnet.MaxPacketSize {
		return nil, fmt.Errorf("l3client: frame length %d exceeds MaxPacketSize %d", n, virtualnet.MaxPacketSize)
	}
	pkt := make([]byte, n)
	if _, err := io.ReadFull(r, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}
