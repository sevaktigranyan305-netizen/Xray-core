package virtualnet

import (
	"net/netip"
	"testing"
)

// TestIPAMAssignDeterministic verifies the same UUID always maps to the
// same IP, which is what the task's "persists in memory for the lifetime
// of the process" guarantee requires.
func TestIPAMAssignDeterministic(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/24")
	a := NewIPAM(p, true)
	ip1, err := a.Assign("user-a")
	if err != nil {
		t.Fatalf("first assign: %v", err)
	}
	ip2, err := a.Assign("user-a")
	if err != nil {
		t.Fatalf("second assign: %v", err)
	}
	if ip1 != ip2 {
		t.Fatalf("expected stable assignment, got %s vs %s", ip1, ip2)
	}
	if !p.Contains(ip1) {
		t.Fatalf("%s is outside subnet %s", ip1, p)
	}
	if ip1 == p.Addr() || ip1 == p.Addr().Next() {
		t.Fatalf("assigned reserved address %s", ip1)
	}
}

// TestIPAMCollisionProbes ensures that when the hashed candidate collides
// we linearly probe for a free slot instead of returning the same IP to
// two users, and that exhaustion is reported cleanly.
// A /29 has 8 addresses; minus network, gateway, broadcast leaves 5
// usable hosts — enough to exercise the probe loop a few times.
func TestIPAMCollisionProbes(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/29")
	a := NewIPAM(p, true)
	ips := make(map[netip.Addr]string)
	for _, u := range []string{"u1", "u2", "u3", "u4", "u5"} {
		ip, err := a.Assign(u)
		if err != nil {
			t.Fatalf("assign %s: %v", u, err)
		}
		if prev, ok := ips[ip]; ok {
			t.Fatalf("collision: %s and %s both got %s", prev, u, ip)
		}
		ips[ip] = u
	}
	if _, err := a.Assign("u6"); err == nil {
		t.Fatal("expected exhaustion error once all hosts are taken")
	}
}

// TestIPAMReverseLookup confirms UUIDOf is consistent with Assign.
func TestIPAMReverseLookup(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), true)
	ip, err := a.Assign("alpha")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := a.UUIDOf(ip)
	if !ok || got != "alpha" {
		t.Fatalf("UUIDOf(%s) = %q,%v; want alpha,true", ip, got, ok)
	}
	if _, ok := a.UUIDOf(netip.MustParseAddr("10.0.0.250")); ok {
		t.Fatal("UUIDOf should return false for unassigned IP")
	}
}

// TestIPAMReserve validates pinned assignments.
func TestIPAMReserve(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), true)
	pin := netip.MustParseAddr("10.0.0.42")
	if err := a.Reserve("pinned", pin); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	got, err := a.Assign("pinned")
	if err != nil {
		t.Fatal(err)
	}
	if got != pin {
		t.Fatalf("expected %s, got %s", pin, got)
	}
	// Reserving the same IP for a different uuid must error.
	if err := a.Reserve("other", pin); err == nil {
		t.Fatal("expected conflict error")
	}
	// Cannot reserve the gateway.
	if err := a.Reserve("gw", netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Fatal("expected error reserving gateway")
	}
}
