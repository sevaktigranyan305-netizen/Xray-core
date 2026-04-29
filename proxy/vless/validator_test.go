package vless_test

import (
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

// TestMemoryValidatorOnDelHookFires confirms that registering an
// OnDel hook makes Del invoke the callback synchronously with the
// MemoryUser that was just removed. The virtualnet IPAM uses this to
// release a deleted user's pinned virtual IP — without the hook, IPs
// would leak across panel deletions until xray restart.
func TestMemoryValidatorOnDelHookFires(t *testing.T) {
	v := new(vless.MemoryValidator)

	id, err := uuid.ParseString("11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	mu := &protocol.MemoryUser{
		Email: "alice@example.com",
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(id),
		},
	}
	if err := v.Add(mu); err != nil {
		t.Fatalf("add: %v", err)
	}

	var seen atomic.Pointer[protocol.MemoryUser]
	v.SetOnDel(func(u *protocol.MemoryUser) {
		seen.Store(u)
	})

	if err := v.Del("alice@example.com"); err != nil {
		t.Fatalf("del: %v", err)
	}
	got := seen.Load()
	if got == nil {
		t.Fatal("OnDel hook did not fire")
	}
	if got.Email != "alice@example.com" {
		t.Fatalf("OnDel got user %q, want alice@example.com", got.Email)
	}
	if got.Account.(*vless.MemoryAccount).ID.String() != id.String() {
		t.Fatalf("OnDel got id %s, want %s", got.Account.(*vless.MemoryAccount).ID.String(), id.String())
	}

	// After Del, the user must be unreachable.
	if v.GetByEmail("alice@example.com") != nil {
		t.Fatal("user still reachable by email after Del")
	}
	if v.Get(id) != nil {
		t.Fatal("user still reachable by id after Del")
	}
}

// TestMemoryValidatorOnDelHookOptional ensures Del still works when no
// hook is registered — the legacy code path stays unchanged.
func TestMemoryValidatorOnDelHookOptional(t *testing.T) {
	v := new(vless.MemoryValidator)
	id, err := uuid.ParseString("22222222-2222-2222-2222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	mu := &protocol.MemoryUser{
		Email: "bob@example.com",
		Account: &vless.MemoryAccount{
			ID: protocol.NewID(id),
		},
	}
	if err := v.Add(mu); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := v.Del("bob@example.com"); err != nil {
		t.Fatalf("del: %v", err)
	}
	if v.GetByEmail("bob@example.com") != nil {
		t.Fatal("user still present after Del")
	}
}

// Reference serial to keep the import used even if future refactors
// remove it from the production code path.
var _ = serial.ToTypedMessage
