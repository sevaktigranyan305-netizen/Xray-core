package virtualnet

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// pipeConn is an in-memory ReadWriteCloser pair used as a stand-in for
// the VLESS stream in tests. It's a simple net.Pipe with explicit Close.
func pipeConn() (io.ReadWriteCloser, io.ReadWriteCloser) {
	a, b := net.Pipe()
	return a, b
}

// TestSwitchPeerToPeerForwarding constructs two endpoints on a single
// switch and verifies that a well-formed IPv4 packet from A addressed to
// B is delivered verbatim to B's stream — exercising the core peer-to-
// peer leg of the task.
func TestSwitchPeerToPeerForwarding(t *testing.T) {
	sw, err := NewSwitch(context.Background(), Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	aSrv, aCli := pipeConn()
	bSrv, bCli := pipeConn()

	aIP := netip.MustParseAddr("10.0.0.2")
	bIP := netip.MustParseAddr("10.0.0.3")

	if _, err := sw.Register(aIP, "user-a", aSrv); err != nil {
		t.Fatalf("register A: %v", err)
	}
	if _, err := sw.Register(bIP, "user-b", bSrv); err != nil {
		t.Fatalf("register B: %v", err)
	}

	// Build an IPv4 packet A -> B. The body is arbitrary; the switch
	// doesn't parse past src/dst.
	pkt := newIPv4(aIP, bIP, []byte("hello"))

	// Send from A's client side (this is how the real VLESS stream
	// would carry packets from the VLESS client to the switch).
	if err := writeFrame(aCli, pkt); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// Read what lands on B's client side and confirm it matches.
	done := make(chan []byte, 1)
	var readErr error
	go func() {
		got, e := readFrame(bCli)
		readErr = e
		done <- got
	}()
	select {
	case got := <-done:
		if readErr != nil {
			t.Fatalf("readFrame on B: %v", readErr)
		}
		if string(got) != string(pkt) {
			t.Fatalf("B received %x, want %x", got, pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for peer packet")
	}
}

// TestSwitchDropsSpoofedSource ensures the anti-spoofing check rejects
// packets whose IPv4 source differs from the endpoint's assigned IP.
// Without this, xray routing rules keyed on sourceIP would be trivially
// bypassable.
func TestSwitchDropsSpoofedSource(t *testing.T) {
	sw, err := NewSwitch(context.Background(), Config{
		Subnet: netip.MustParsePrefix("10.0.0.0/24"),
	})
	if err != nil {
		t.Fatalf("NewSwitch: %v", err)
	}
	defer sw.Close()

	aSrv, aCli := pipeConn()
	bSrv, bCli := pipeConn()
	if _, err := sw.Register(netip.MustParseAddr("10.0.0.2"), "a", aSrv); err != nil {
		t.Fatalf("reg a: %v", err)
	}
	if _, err := sw.Register(netip.MustParseAddr("10.0.0.3"), "b", bSrv); err != nil {
		t.Fatalf("reg b: %v", err)
	}

	// A sends a packet claiming to be from 10.0.0.99 (unassigned). The
	// switch must drop it silently — B receives nothing within the
	// read deadline.
	pkt := newIPv4(netip.MustParseAddr("10.0.0.99"), netip.MustParseAddr("10.0.0.3"), []byte("x"))
	if err := writeFrame(aCli, pkt); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// Use a short deadline; expect EOF or timeout.
	var wg sync.WaitGroup
	wg.Add(1)
	gotData := false
	go func() {
		defer wg.Done()
		_ = bCli.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := readFrame(bCli); err == nil {
			gotData = true
		}
	}()
	wg.Wait()
	if gotData {
		t.Fatal("spoofed packet was delivered; anti-spoofing failed")
	}
}

// newIPv4 builds a minimal IPv4 packet with the given src/dst and
// payload. The checksum is zeroed — the switch never validates it, and
// real packets on a userspace link often rely on upper layers.
func newIPv4(src, dst netip.Addr, payload []byte) []byte {
	// Total length = 20-byte header + payload.
	total := 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45 // Version 4, IHL 5
	b[1] = 0x00
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	b[8] = 64   // TTL
	b[9] = 0xFD // experimental protocol, benign
	s := src.As4()
	d := dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], payload)
	return b
}
