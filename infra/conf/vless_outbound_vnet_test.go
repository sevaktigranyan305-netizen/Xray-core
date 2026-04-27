package conf_test

import (
	"encoding/json"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless/outbound"
)

// TestOutboundDetour_TopLevelVirtualNetwork_Vless verifies that the
// "virtualNetwork" block, when written at the OUTBOUND top level
// (sibling of "settings"/"streamSettings") as documented for the
// client-side config, is spliced into VLESS settings before parsing
// and ends up populated on outbound.Config.VirtualNetwork.
//
// Without the splice in OutboundDetourConfig.Build, the field is
// silently dropped because the JSON parser only inspects "settings".
func TestOutboundDetour_TopLevelVirtualNetwork_Vless(t *testing.T) {
	raw := []byte(`{
		"protocol": "vless",
		"settings": {
			"vnext": [{
				"address": "109.172.115.130",
				"port": 443,
				"users": [{
					"id": "62cd80bf-c4be-401b-a1c9-8fb4deca8e53",
					"encryption": "none"
				}]
			}]
		},
		"virtualNetwork": {
			"enabled": true,
			"subnet": "10.0.0.0/24",
			"defaultRoute": true
		}
	}`)

	var cfg OutboundDetourConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal OutboundDetourConfig: %v", err)
	}
	if cfg.VirtualNetwork == nil {
		t.Fatal("VirtualNetwork field on OutboundDetourConfig was not populated from the top level")
	}

	handler, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tm := handler.ProxySettings
	if tm == nil {
		t.Fatal("nil ProxySettings")
	}
	msg, err := tm.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	out, ok := msg.(*outbound.Config)
	if !ok {
		t.Fatalf("expected *outbound.Config, got %T", msg)
	}
	if out.VirtualNetwork == nil {
		t.Fatal("outbound.Config.VirtualNetwork is nil — top-level virtualNetwork was NOT spliced into settings")
	}
	if !out.VirtualNetwork.Enabled {
		t.Errorf("VirtualNetwork.Enabled = false, want true")
	}
	if out.VirtualNetwork.Subnet != "10.0.0.0/24" {
		t.Errorf("VirtualNetwork.Subnet = %q, want %q", out.VirtualNetwork.Subnet, "10.0.0.0/24")
	}
	if !out.VirtualNetwork.DefaultRoute {
		t.Errorf("VirtualNetwork.DefaultRoute = false, want true")
	}
}

// TestOutboundDetour_InsideSettingsVirtualNetwork_Vless verifies the
// existing inside-"settings" location still works and isn't broken
// by the splice.
func TestOutboundDetour_InsideSettingsVirtualNetwork_Vless(t *testing.T) {
	raw := []byte(`{
		"protocol": "vless",
		"settings": {
			"vnext": [{
				"address": "109.172.115.130",
				"port": 443,
				"users": [{
					"id": "62cd80bf-c4be-401b-a1c9-8fb4deca8e53",
					"encryption": "none"
				}]
			}],
			"virtualNetwork": {
				"enabled": true,
				"subnet": "10.0.0.0/24"
			}
		}
	}`)

	var cfg OutboundDetourConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	handler, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	msg, err := handler.ProxySettings.GetInstance()
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	out := msg.(*outbound.Config)
	if out.VirtualNetwork == nil || !out.VirtualNetwork.Enabled {
		t.Fatal("inside-settings virtualNetwork.enabled regressed")
	}
}
