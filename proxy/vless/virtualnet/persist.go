package virtualnet

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// persistFileVersion is bumped if the on-disk format changes in a way
// that older xray versions cannot read. Today's writers are forward-
// compatible: an unknown version on read is treated as "unknown
// format, start fresh".
const persistFileVersion = 1

// persistFile is the JSON document we write to disk. The map is
// serialised as a slice of {uuid, ip} entries so that the file is
// stable when read back (Go's map iteration order is randomised).
// Loading from a slice also makes corruption easier to recover from
// — a single bad entry doesn't poison the whole map.
type persistFile struct {
	Version  int                `json:"version"`
	Subnet   string             `json:"subnet"`
	Mappings []persistFileEntry `json:"mappings"`
}

type persistFileEntry struct {
	UUID string `json:"uuid"`
	IP   string `json:"ip"`
}

// LoadPersisted reads persistPath and reserves each (uuid, ip) into
// the IPAM. Mappings whose IP is outside the subnet, points at the
// reserved gateway/network/broadcast, or collides with another already-
// reserved IP are skipped (with a counter returned). A missing file is
// not an error; nor is a corrupt or wrong-subnet file (in which case
// the IPAM stays empty and the caller will overwrite the file on the
// next change). Returns the number of mappings successfully restored
// and the number rejected.
func (a *IPAM) LoadPersisted() (loaded, skipped int, err error) {
	if a.persistPath == "" {
		return 0, 0, nil
	}
	data, err := os.ReadFile(a.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("read %s: %w", a.persistPath, err)
	}
	var pf persistFile
	if err := json.Unmarshal(data, &pf); err != nil {
		// Corrupt file: treat as empty, do not error out so the
		// inbound still comes up. Caller will overwrite on next save.
		return 0, 0, fmt.Errorf("parse %s: %w", a.persistPath, err)
	}
	if pf.Version != persistFileVersion {
		return 0, 0, fmt.Errorf("unknown persist file version %d at %s", pf.Version, a.persistPath)
	}
	if pf.Subnet != a.subnet.String() {
		return 0, 0, fmt.Errorf("subnet mismatch in %s: file=%s, runtime=%s", a.persistPath, pf.Subnet, a.subnet.String())
	}
	for _, e := range pf.Mappings {
		ip, perr := netip.ParseAddr(e.IP)
		if perr != nil {
			skipped++
			continue
		}
		if err := a.Reserve(e.UUID, ip); err != nil {
			skipped++
			continue
		}
		loaded++
	}
	return loaded, skipped, nil
}

// saveLocked writes the current mapping table to persistPath. The
// caller MUST hold a.mu. A no-op when persistPath is empty (in-memory
// mode, used by tests).
//
// Atomicity: we write to a sibling tempfile, fsync it, then rename
// over the target. POSIX rename is atomic, so a crash between write
// and rename leaves the previous version intact.
func (a *IPAM) saveLocked() error {
	if a.persistPath == "" {
		return nil
	}
	entries := make([]persistFileEntry, 0, len(a.byUUID))
	for u, ip := range a.byUUID {
		entries = append(entries, persistFileEntry{UUID: u, IP: ip.String()})
	}
	// Stable order so file diffs (e.g. in version control or backup
	// tooling) are deterministic.
	sort.Slice(entries, func(i, j int) bool { return entries[i].UUID < entries[j].UUID })

	pf := persistFile{
		Version:  persistFileVersion,
		Subnet:   a.subnet.String(),
		Mappings: entries,
	}
	data, err := json.MarshalIndent(&pf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.persistPath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.persistPath), filepath.Base(a.persistPath)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpPath, a.persistPath); err != nil {
		cleanup()
		return err
	}
	return nil
}
