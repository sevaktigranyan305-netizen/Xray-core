package virtualnet

import (
	"net/netip"
	"path/filepath"
	"testing"
)

// TestIPAMAssignDeterministic verifies the same UUID always maps to the
// same IP within an IPAM instance.
func TestIPAMAssignDeterministic(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/24")
	a := NewIPAM(p, "")
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

// TestIPAMAssignsLowestFreeFromGateway exercises the core requirement
// of this design: addresses are handed out sequentially starting from
// gateway+1 — 10.0.0.2, 10.0.0.3, 10.0.0.4 — regardless of UUID
// content. There is no per-UUID hashing.
func TestIPAMAssignsLowestFreeFromGateway(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), "")
	for i, want := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		got, err := a.Assign(uuidStr(i))
		if err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
		if got.String() != want {
			t.Fatalf("assign %d: got %s, want %s", i, got, want)
		}
	}
}

// TestIPAMReusesLowestFreeAfterRelease checks the panel-deletion path:
// after a user is released, their slot becomes the lowest free address
// and is handed out before any address higher than the current
// high-water mark.
func TestIPAMReusesLowestFreeAfterRelease(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), "")
	for i := 0; i < 4; i++ {
		if _, err := a.Assign(uuidStr(i)); err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
	}
	// Layout now: u0=.2, u1=.3, u2=.4, u3=.5. Release u2 (10.0.0.4).
	a.Release(uuidStr(2))
	if _, ok := a.Lookup(uuidStr(2)); ok {
		t.Fatal("released uuid still present in Lookup")
	}
	// Next user must reclaim 10.0.0.4, not jump to .6.
	got, err := a.Assign(uuidStr(99))
	if err != nil {
		t.Fatalf("post-release assign: %v", err)
	}
	if got.String() != "10.0.0.4" {
		t.Fatalf("expected reused 10.0.0.4, got %s", got)
	}
	// And the next one after that must be .6 (next slot above the
	// high-water mark .5).
	got2, err := a.Assign(uuidStr(100))
	if err != nil {
		t.Fatalf("subsequent assign: %v", err)
	}
	if got2.String() != "10.0.0.6" {
		t.Fatalf("expected 10.0.0.6, got %s", got2)
	}
}

// TestIPAMExhaustion confirms allocation fails cleanly once the host
// space is full.
func TestIPAMExhaustion(t *testing.T) {
	// /29 has 8 addrs minus network/gateway/broadcast = 5 hosts.
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/29"), "")
	for i := 0; i < 5; i++ {
		if _, err := a.Assign(uuidStr(i)); err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
	}
	if _, err := a.Assign("overflow"); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

// TestIPAMReverseLookup confirms UUIDOf is consistent with Assign.
func TestIPAMReverseLookup(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), "")
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

// TestIPAMReserve validates pinned assignments via the loader path.
func TestIPAMReserve(t *testing.T) {
	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), "")
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

// TestIPAMPersistRoundtrip verifies that on-disk state survives an
// IPAM restart: a fresh IPAM constructed against the same file must
// see the same UUID -> IP table after LoadPersisted, without any new
// allocation.
func TestIPAMPersistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipam.json")
	subnet := netip.MustParsePrefix("10.0.0.0/24")

	a := NewIPAM(subnet, path)
	for i := 0; i < 3; i++ {
		if _, err := a.Assign(uuidStr(i)); err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
	}
	want := a.Snapshot()

	b := NewIPAM(subnet, path)
	loaded, skipped, err := b.LoadPersisted()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded != 3 || skipped != 0 {
		t.Fatalf("loaded=%d skipped=%d, want 3/0", loaded, skipped)
	}
	got := b.Snapshot()
	if len(got) != len(want) {
		t.Fatalf("snapshot size mismatch: got %d, want %d", len(got), len(want))
	}
	for u, ip := range want {
		if got[u] != ip {
			t.Fatalf("after reload, %s -> %s, want %s", u, got[u], ip)
		}
	}
}

// TestIPAMReconcileDropsStale exercises the "user deleted while xray
// was offline" flow: persisted file has 3 mappings, only 2 of those
// UUIDs are in the active client list, the third must be removed and
// its slot reused on the next Assign.
func TestIPAMReconcileDropsStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipam.json")
	subnet := netip.MustParsePrefix("10.0.0.0/24")

	a := NewIPAM(subnet, path)
	for i := 0; i < 3; i++ {
		if _, err := a.Assign(uuidStr(i)); err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
	}
	// Layout: u0=.2, u1=.3, u2=.4. Drop u1 from active list.
	released := a.Reconcile([]string{uuidStr(0), uuidStr(2)})
	if released != 1 {
		t.Fatalf("Reconcile released=%d, want 1", released)
	}
	if _, ok := a.Lookup(uuidStr(1)); ok {
		t.Fatal("u1 should have been released")
	}
	// The freed .3 slot should be the next allocation.
	got, err := a.Assign("newcomer")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "10.0.0.3" {
		t.Fatalf("expected reused 10.0.0.3, got %s", got)
	}

	// Verify Reconcile persisted the change: a fresh IPAM loading
	// from the same file must not see u1 either.
	b := NewIPAM(subnet, path)
	if _, _, err := b.LoadPersisted(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := b.Lookup(uuidStr(1)); ok {
		t.Fatal("u1 should not be present after Reconcile + reload")
	}
}

// TestIPAMSubnetMismatchResetsState makes sure a persisted file written
// for subnet A is ignored when a new IPAM is configured for subnet B
// (e.g. the user changed the subnet in their config). The mappings
// would otherwise be invalid.
func TestIPAMSubnetMismatchResetsState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipam.json")

	a := NewIPAM(netip.MustParsePrefix("10.0.0.0/24"), path)
	if _, err := a.Assign("u0"); err != nil {
		t.Fatal(err)
	}

	b := NewIPAM(netip.MustParsePrefix("172.16.0.0/16"), path)
	loaded, _, err := b.LoadPersisted()
	if err == nil {
		t.Fatal("expected subnet mismatch error")
	}
	if loaded != 0 {
		t.Fatalf("expected zero loaded mappings on mismatch, got %d", loaded)
	}
	if _, ok := b.Lookup("u0"); ok {
		t.Fatal("subnet-mismatched mapping must not be reused")
	}
}

func uuidStr(i int) string {
	// Fixed prefix; the suffix bytes are what change per i. Content
	// is irrelevant — the new IPAM does not hash UUIDs.
	return "00000000-0000-0000-0000-00000000000" + string(rune('0'+i))
}
