//go:build !linux && !darwin

package l3client

import "errors"

// newDevice is a placeholder for platforms other than Linux and Darwin.
// Windows/FreeBSD/OpenBSD TUN support is out of scope for the first
// iteration; builds on those platforms will still succeed but any attempt
// to enable virtualNetwork on a VLESS outbound returns a clear error at
// runtime.
func newDevice(cfg deviceConfig) (Device, error) {
	return nil, errors.New("l3client: VLESS virtualNetwork client is only supported on linux and darwin")
}
