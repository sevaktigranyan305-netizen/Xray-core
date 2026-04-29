package virtualnet

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// IPAM assigns and remembers virtual IPs for users.
//
// Allocation strategy: deterministic and sequential. The first usable
// host of the subnet (subnet.Addr()+1) is reserved as the gateway.
// Subsequent users get the lowest free host address, in ascending
// order: 10.0.0.2, 10.0.0.3, 10.0.0.4 … For each new UUID we scan from
// gateway+1 upwards and pick the first slot not currently held by
// another UUID. When a UUID is removed (Release / Reconcile drops it),
// its address goes back into the pool and may be reused by a later
// Assign — again, the lowest free slot wins.
//
// Mappings are owned by the IPAM in memory. When a non-empty
// PersistPath is configured the table is also serialised to disk on
// every change (atomic write via temp file + rename). On startup the
// file is loaded back so a UUID keeps the same address across xray
// restarts. Reconcile drops mappings whose UUID is no longer in the
// inbound's client list, which is how "user deleted from the panel
// while xray was offline" gets cleaned up.
type IPAM struct {
	subnet      netip.Prefix
	gateway     netip.Addr
	broadcast   netip.Addr
	persistPath string

	mu     sync.Mutex
	byUUID map[string]netip.Addr
	inUse  map[netip.Addr]string // IP -> UUID (reverse map for collision checks)
}

// NewIPAM constructs an IPAM for the given subnet. If persistPath is
// non-empty the file is loaded as initial state (missing/corrupt files
// are treated as empty with a warning logged by the caller). The
// caller is responsible for ensuring the prefix is valid IPv4;
// NewSwitch does this.
func NewIPAM(subnet netip.Prefix, persistPath string) *IPAM {
	gateway := subnet.Addr().Next()
	bcast := directedBroadcast(subnet)
	return &IPAM{
		subnet:      subnet,
		gateway:     gateway,
		broadcast:   bcast,
		persistPath: persistPath,
		byUUID:      make(map[string]netip.Addr),
		inUse:       make(map[netip.Addr]string),
	}
}

// Assign returns the IP for uuid, allocating one if needed. It is safe
// for concurrent use. Allocation is sequential: the lowest free host
// address (gateway+1, gateway+2, …) is returned.
func (a *IPAM) Assign(uuid string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.byUUID[uuid]; ok {
		return ip, nil
	}

	ip, ok := a.lowestFreeLocked()
	if !ok {
		return netip.Addr{}, errors.New("virtualnet: subnet exhausted")
	}
	a.byUUID[uuid] = ip
	a.inUse[ip] = uuid
	if err := a.saveLocked(); err != nil {
		// Roll back the in-memory write so the on-disk and in-memory
		// views never diverge. Returning the error gives the caller a
		// chance to log; the connect attempt will fail and the user
		// will retry.
		delete(a.byUUID, uuid)
		delete(a.inUse, ip)
		return netip.Addr{}, fmt.Errorf("virtualnet: persist ipam: %w", err)
	}
	return ip, nil
}

// Lookup returns the IP for uuid, if any.
func (a *IPAM) Lookup(uuid string) (netip.Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.byUUID[uuid]
	return ip, ok
}

// UUIDOf is the reverse of Lookup: it returns the UUID assigned to ip,
// or ("", false) if the slot is unassigned. Used by the VLESS inbound's
// ConnHandler to attach the original MemoryUser to synthesised session
// contexts when traffic from a virtual IP egresses through xray.
func (a *IPAM) UUIDOf(ip netip.Addr) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	uuid, ok := a.inUse[ip]
	return uuid, ok
}

// Release frees the slot held by uuid, if any. It is the inverse of
// Assign and is intended to be called when a user is deleted from the
// inbound's client list (e.g. via the panel). The freed address can
// then be reused by the next Assign whose UUID has no existing
// mapping. Persistent state is updated on success.
func (a *IPAM) Release(uuid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.byUUID[uuid]
	if !ok {
		return
	}
	delete(a.byUUID, uuid)
	delete(a.inUse, ip)
	// Best-effort save. Failure here is logged by the caller but does
	// not roll back: the user has already been deleted upstream and
	// re-pinning their old IP would just let it leak into the persisted
	// file across restarts.
	_ = a.saveLocked()
}

// Reconcile drops mappings whose UUID is not present in activeUUIDs.
// This is called once at startup with the current set of client UUIDs
// from the inbound config, so that any mapping persisted on disk for a
// user that has since been removed from the panel is cleaned up
// before the first connect. Returns the number of mappings dropped.
func (a *IPAM) Reconcile(activeUUIDs []string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	active := make(map[string]struct{}, len(activeUUIDs))
	for _, u := range activeUUIDs {
		active[u] = struct{}{}
	}
	released := 0
	for u, ip := range a.byUUID {
		if _, ok := active[u]; ok {
			continue
		}
		delete(a.byUUID, u)
		delete(a.inUse, ip)
		released++
	}
	if released > 0 {
		_ = a.saveLocked()
	}
	return released
}

// Reserve forces an assignment for uuid -> ip, erroring if the IP is
// already taken by a different UUID or falls outside the subnet. This
// is what the persistence loader uses to rehydrate state without going
// through the lowest-free allocator.
func (a *IPAM) Reserve(uuid string, ip netip.Addr) error {
	if !a.subnet.Contains(ip) {
		return fmt.Errorf("virtualnet: %s is outside subnet %s", ip, a.subnet)
	}
	if !a.isUsable(ip) {
		return fmt.Errorf("virtualnet: %s is reserved (gateway or broadcast)", ip)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if owner, ok := a.inUse[ip]; ok && owner != uuid {
		return fmt.Errorf("virtualnet: %s already assigned to %s", ip, owner)
	}
	if prev, ok := a.byUUID[uuid]; ok && prev != ip {
		delete(a.inUse, prev)
	}
	a.byUUID[uuid] = ip
	a.inUse[ip] = uuid
	return nil
}

// Snapshot returns a copy of the current UUID->IP table. Intended for
// tests and for the persistence layer's serialisation step. Holding
// the IPAM lock here is safe because callers must not call back into
// the IPAM while holding the snapshot.
func (a *IPAM) Snapshot() map[string]netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]netip.Addr, len(a.byUUID))
	for k, v := range a.byUUID {
		out[k] = v
	}
	return out
}

// lowestFreeLocked scans from gateway+1 upwards for the first usable
// address that no UUID currently holds. The caller must hold a.mu.
// Returns ok=false when the subnet is exhausted.
func (a *IPAM) lowestFreeLocked() (netip.Addr, bool) {
	cur := a.gateway.Next()
	for a.subnet.Contains(cur) {
		if !a.isUsable(cur) {
			cur = cur.Next()
			continue
		}
		if _, taken := a.inUse[cur]; !taken {
			return cur, true
		}
		cur = cur.Next()
	}
	return netip.Addr{}, false
}

// isUsable filters out the network, gateway and broadcast IPs.
func (a *IPAM) isUsable(ip netip.Addr) bool {
	if !a.subnet.Contains(ip) {
		return false
	}
	if ip == a.subnet.Addr() || ip == a.gateway || ip == a.broadcast {
		return false
	}
	return true
}

// directedBroadcast returns the all-ones broadcast for a prefix. For
// /32 the broadcast and network collapse onto the same address; the
// subnet size check in NewSwitch prevents that configuration anyway.
func directedBroadcast(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return p.Addr()
	}
	hostBits := 32 - p.Bits()
	base := p.Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v |= hostMask(hostBits)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func hostMask(hostBits int) uint32 {
	if hostBits <= 0 {
		return 0
	}
	if hostBits >= 32 {
		return ^uint32(0)
	}
	return (uint32(1) << hostBits) - 1
}
