package l3client

import (
	"net/netip"
	"strings"
	"testing"
)

// TestNewClient_AssignedIPValidation covers the constructor-time
// guard rails on the optional AssignedIP knob. The caller-provided
// value is rejected up-front so a misconfigured outbound never reaches
// the dial-and-handshake path; this matters because a bad AssignedIP
// would otherwise only surface at first connect, after several
// seconds of retry backoff in runL3Bootstrap.
func TestNewClient_AssignedIPValidation(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")

	tests := []struct {
		name       string
		assignedIP netip.Addr
		wantErr    string
	}{
		{
			name:       "zero is allowed (legacy mode, no validation)",
			assignedIP: netip.Addr{},
		},
		{
			name:       "valid IPv4 inside subnet",
			assignedIP: netip.MustParseAddr("10.0.0.5"),
		},
		{
			name:       "outside subnet rejected",
			assignedIP: netip.MustParseAddr("192.168.1.1"),
			wantErr:    "outside subnet",
		},
		{
			// IPv6 has no place in a v4-only L3 client; reject it
			// loudly rather than letting netip.Addr.Is4() return
			// false at runtime in subtler places.
			name:       "IPv6 rejected",
			assignedIP: netip.MustParseAddr("fe80::1"),
			wantErr:    "must be IPv4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(Config{
				Subnet:     subnet,
				AssignedIP: tt.assignedIP,
			})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
