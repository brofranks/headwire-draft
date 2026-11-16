package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/dns"
)

func TestManagedDNSFamiliesAndClose(t *testing.T) {
	ip4, ip6 := netip.MustParseAddr("100.100.100.100"), netip.MustParseAddr("fd7a:115c:a1e0::53")
	for _, servers := range [][]netip.Addr{{ip4}, {ip6}, {ip4, ip6}} {
		raw := &recordingDNS{}
		m := &managedDNS{os: raw, servers: servers}
		if err := m.SetDNS(dns.OSConfig{Nameservers: []netip.Addr{ip4, ip6}}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(raw.set.Nameservers, servers) {
			t.Fatalf("servers = %v, want %v", raw.set.Nameservers, servers)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if !raw.closed {
			t.Fatal("OS DNS not restored")
		}
		if err := m.SetDNS(dns.OSConfig{Nameservers: servers}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late SetDNS = %v", err)
		}
	}
}

type failedDNSClose struct{ dns.OSConfigurator }

func (failedDNSClose) Close() error { return errors.New("resolver restoration failed") }

func TestDNSRestorationFailureIsReported(t *testing.T) {
	var message string
	e := &Engine{
		hostDNS: &managedDNS{os: failedDNSClose{}},
		logf:    func(format string, args ...any) { message = fmt.Sprintf(format, args...) },
	}
	e.Close()
	if !strings.Contains(message, "DNS restore: resolver restoration failed") {
		t.Fatal(message)
	}
}
