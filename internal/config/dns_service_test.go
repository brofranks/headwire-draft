package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestDNSServiceSelection(t *testing.T) {
	for _, tc := range []struct{ name, addresses, policy, servers, wantError string }{
		{"disabled", "100.64.0.1/32", "", "[]", ""},
		{"direct", "100.64.0.1/32", "DNS = 192.0.2.53\n", "[]", ""},
		{"ipv4", "100.64.0.1/32", "[DNS]\nHost = host.example 192.0.2.1\n", "[100.100.100.100]", ""},
		{"ipv6", "fd00::1/128", "[DNS]\nRoute = lab.example\n", "[fd7a:115c:a1e0::53]", ""},
		{"dual", "100.64.0.1/32, fd00::1/128", "[DNS]\nRoute = lab.example 192.0.2.53\n", "[100.100.100.100 fd7a:115c:a1e0::53]", ""},
		{"assigned", "100.100.100.100/32", "[DNS]\nHost = host.example 192.0.2.1\n", "", "cannot be an [Interface] Address"},
		{"self upstream", "100.64.0.1/32", "DNS = 100.100.100.100\n", "", "not an upstream"},
		{"mapped self upstream", "100.64.0.1/32", "DNS = ::ffff:100.100.100.100\n", "", "not an upstream"},
		{"self route", "100.64.0.1/32", "[DNS]\nRoute = lab.example fd7a:115c:a1e0::53\n", "", "not an upstream"},
		{"shadowed route", "100.64.0.1/32", "[DNS]\nRoute = corp.example\nRoute = child.corp.example 192.0.2.53\n", "", "beneath authoritative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("[Interface]\nPrivateKey = " + keyA + "\nAddress = " + tc.addresses + "\n" + tc.policy))
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Parse = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprint(cfg.DNSServiceIPs()); got != tc.servers {
				t.Fatalf("servers = %s, want %s", got, tc.servers)
			}
		})
	}
}
