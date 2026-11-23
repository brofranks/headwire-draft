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
		{"ipv4", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\nHost = host.example 192.0.2.1\n", "[100.64.0.53]", ""},
		{"ipv6", "fd00::1/128", "[DNS]\nAddress = fd00::53\nRoute = lab.example\n", "[fd00::53]", ""},
		{"dual", "100.64.0.1/32, fd00::1/128", "[DNS]\nAddress = 100.64.0.53 fd00::53\nRoute = lab.example 192.0.2.53\n", "[100.64.0.53 fd00::53]", ""},
		{"one family", "100.64.0.1/32, fd00::1/128", "[DNS]\nAddress = fd00::53\nHost = host.example 192.0.2.1\n", "[fd00::53]", ""},
		{"address only", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\n", "[100.64.0.53]", ""},
		{"former service address", "100.64.0.1/32", "DNS = 100.100.100.100\n", "[]", ""},
		{"missing", "100.64.0.1/32", "[DNS]\nHost = host.example 192.0.2.1\n", "", "[DNS] Address is required"},
		{"missing for doh", "100.64.0.1/32", "DNS = 45.90.28.0\n", "", "[DNS] Address is required"},
		{"family", "100.64.0.1/32", "[DNS]\nAddress = fd00::53\nHost = host.example 192.0.2.1\n", "", "requires an [Interface] Address of the same family"},
		{"two of a family", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53, 100.64.0.54\n", "", "at most one address per family"},
		{"repeated key", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\nAddress = fd00::53\n", "", "duplicate key"},
		{"loopback", "100.64.0.1/32", "[DNS]\nAddress = 127.0.0.53\n", "", "not a unicast address"},
		{"link-local", "fd00::1/128", "[DNS]\nAddress = fe80::53\n", "", "not a unicast address"},
		{"mapped", "fd00::1/128", "[DNS]\nAddress = ::ffff:100.64.0.53\n", "", "not a unicast address"},
		{"prefix", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53/32\n", "", "invalid address"},
		{"assigned", "100.64.0.53/32", "[DNS]\nAddress = 100.64.0.53\n", "", "cannot be an [Interface] Address"},
		{"self upstream", "100.64.0.1/32", "DNS = 100.64.0.53\n[DNS]\nAddress = 100.64.0.53\n", "", "not an upstream"},
		{"mapped self upstream", "100.64.0.1/32", "DNS = ::ffff:100.64.0.53\n[DNS]\nAddress = 100.64.0.53\n", "", "not an upstream"},
		{"self route", "fd00::1/128", "[DNS]\nAddress = fd00::53\nRoute = lab.example fd00::53\n", "", "not an upstream"},
		{"peer address", "100.64.0.1/24", "[DNS]\nAddress = 100.64.0.2\n[Peer]\nPublicKey = " + keyB + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 100.64.0.2/32\n", "", "is the [DNS] Address"},
		{"inside peer prefix", "100.64.0.1/24", "[DNS]\nAddress = 100.64.0.53\n[Peer]\nPublicKey = " + keyB + "\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", "[100.64.0.53]", ""},
		{"shadowed route", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\nRoute = corp.example\nRoute = child.corp.example 192.0.2.53\n", "", "beneath authoritative"},
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
			if got := fmt.Sprint(cfg.DNS.Addresses); got != tc.servers {
				t.Fatalf("servers = %s, want %s", got, tc.servers)
			}
		})
	}
}
