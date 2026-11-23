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
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
)

func TestManagedDNSFamiliesAndClose(t *testing.T) {
	quad4, quad6 := tsaddr.TailscaleServiceIP(), tsaddr.TailscaleServiceIPv6()
	ip4, ip6 := netip.MustParseAddr("100.64.0.53"), netip.MustParseAddr("fd00::53")
	upstream := netip.MustParseAddr("192.0.2.53")
	for _, servers := range [][]netip.Addr{{ip4}, {ip6}, {ip4, ip6}} {
		raw := &recordingDNS{}
		m := &managedDNS{os: withBase{raw, dns.OSConfig{
			Nameservers: []netip.Addr{ip4, upstream, ip6},
			Resolvers: []*dnstype.Resolver{
				{Addr: netip.AddrPortFrom(ip6, 53).String()},
				{Addr: netip.AddrPortFrom(upstream, 53).String()},
			},
		}}, servers: servers}
		if err := m.SetDNS(dns.OSConfig{Nameservers: []netip.Addr{quad4, upstream, quad6}}); err != nil {
			t.Fatal(err)
		}
		want := slices.Clone(servers)
		if want[0].Is4() {
			want = slices.Insert(want, 1, upstream)
		} else {
			want = slices.Insert(want, 0, upstream)
		}
		if !slices.Equal(raw.set.Nameservers, want) {
			t.Fatalf("servers = %v, want %v", raw.set.Nameservers, want)
		}
		base, err := m.GetBaseConfig()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range base.Resolvers {
			if ap := netip.MustParseAddrPort(r.Addr); slices.Contains(servers, ap.Addr()) {
				t.Fatalf("base resolvers include the local resolver: %v", base.Resolvers)
			}
		}
		if slices.ContainsFunc(base.Nameservers, func(ip netip.Addr) bool { return slices.Contains(servers, ip) }) {
			t.Fatalf("base nameservers include the local resolver: %v", base.Nameservers)
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

// withBase reports a fixed base configuration from the host.
type withBase struct {
	*recordingDNS
	base dns.OSConfig
}

func (w withBase) GetBaseConfig() (dns.OSConfig, error) { return w.base, nil }

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
