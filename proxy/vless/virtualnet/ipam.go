package virtualnet

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// IPAM assigns and remembers virtual IPs for users. Mappings are kept in
// memory for the lifetime of the process, matching the "persists in
// memory for the lifetime of the process" requirement in the task.
//
// Assignment strategy:
//
//  1. If a UUID has already been assigned an IP, return that IP.
//
//  2. Otherwise derive a deterministic candidate IP from SHA-1(uuid)
//     folded into the subnet's host range. Skip the network, gateway and
//     broadcast addresses, plus any candidate already taken — in which
//     case we linearly probe forward until a free slot is found. This
//     gives stable assignments in the common case while still handling
//     collisions gracefully.
//
//  3. If every host is taken, return an error. For a /24 that means 253
//     concurrent users, which is well beyond the expected single-host
//     scale.
//
// The persistMapping flag is reserved for a future on-disk persistence
// backend. Today it is honoured only insofar as assignments are never
// released when users disconnect — they remain in the table so the same
// user gets the same IP on reconnect. Set to false to release IPs on
// Remove().
type IPAM struct {
	subnet         netip.Prefix
	gateway        netip.Addr
	broadcast      netip.Addr
	persistMapping bool

	mu       sync.Mutex
	byUUID   map[string]netip.Addr
	inUse    map[netip.Addr]string // IP -> UUID (reverse map for collision checks)
	hostBits int
}

// NewIPAM constructs an IPAM for the given subnet. The caller is
// responsible for ensuring the prefix is valid IPv4; NewSwitch does this.
func NewIPAM(subnet netip.Prefix, persistMapping bool) *IPAM {
	gateway := subnet.Addr().Next()
	// Compute the directed broadcast: all-ones host portion. We reject
	// assigning that to a user because some stacks treat it specially.
	hostBits := 32 - subnet.Bits()
	bcast := directedBroadcast(subnet)
	return &IPAM{
		subnet:         subnet,
		gateway:        gateway,
		broadcast:      bcast,
		persistMapping: persistMapping,
		byUUID:         make(map[string]netip.Addr),
		inUse:          make(map[netip.Addr]string),
		hostBits:       hostBits,
	}
}

// Assign returns the IP for uuid, allocating one if needed. It is safe
// for concurrent use.
func (a *IPAM) Assign(uuid string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.byUUID[uuid]; ok {
		return ip, nil
	}

	candidate := a.deterministicCandidate(uuid)
	for i := 0; i < a.hostSpace(); i++ {
		ip := a.advance(candidate, i)
		if !a.isUsable(ip) {
			continue
		}
		if _, taken := a.inUse[ip]; taken {
			continue
		}
		a.byUUID[uuid] = ip
		a.inUse[ip] = uuid
		return ip, nil
	}
	return netip.Addr{}, errors.New("virtualnet: subnet exhausted")
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

// Remove releases an assignment. It is a no-op if the UUID is unknown.
// When persistMapping is true the mapping is retained so a future Assign
// for the same UUID returns the same IP.
func (a *IPAM) Remove(uuid string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.persistMapping {
		return
	}
	if ip, ok := a.byUUID[uuid]; ok {
		delete(a.byUUID, uuid)
		delete(a.inUse, ip)
	}
}

// Reserve forces an assignment for uuid -> ip, erroring if the IP is
// already taken by a different UUID or falls outside the subnet. Useful
// if a future config backend wants to pre-populate pinned assignments.
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

// hostSpace is the number of candidate host addresses we consider (2^h).
// We accept a small amount of wasted iteration for the reserved
// network/gateway/broadcast slots.
func (a *IPAM) hostSpace() int {
	if a.hostBits >= 31 {
		// Guard: a /0 or /1 is meaningless here; cap at something sane.
		return 1 << 30
	}
	return 1 << a.hostBits
}

// deterministicCandidate folds a SHA-1 of the UUID into the host portion
// of the subnet. SHA-1 is used only as a stable hash — no cryptographic
// property is required.
func (a *IPAM) deterministicCandidate(uuid string) netip.Addr {
	sum := sha1.Sum([]byte(uuid))
	offset := (uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])) & hostMask(a.hostBits)
	base := a.subnet.Addr().As4()
	net := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	// Zero the host bits of the network address, then OR in the host
	// portion of the hash.
	net &= ^hostMask(a.hostBits)
	ip := net | offset
	return uint32ToAddr(ip)
}

// advance returns candidate+delta (wrapping within the subnet). Used to
// linearly probe after the hashed candidate collides.
func (a *IPAM) advance(candidate netip.Addr, delta int) netip.Addr {
	u := addrToUint32(candidate)
	host := u & hostMask(a.hostBits)
	net := u & ^hostMask(a.hostBits)
	host = (host + uint32(delta)) & hostMask(a.hostBits)
	return uint32ToAddr(net | host)
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
	return uint32ToAddr(v)
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

func addrToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
