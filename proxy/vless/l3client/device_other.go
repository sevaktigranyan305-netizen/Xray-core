//go:build !linux && !darwin && !android && !windows

package l3client

import "errors"

// newDevice is a placeholder for platforms without a real device backend.
// Builds on those platforms still succeed but any attempt to enable
// virtualNetwork on a VLESS outbound returns a clear error at runtime.
func newDevice(cfg deviceConfig) (Device, error) {
	return nil, errors.New("l3client: VLESS virtualNetwork client is only supported on linux, android, darwin and windows")
}
