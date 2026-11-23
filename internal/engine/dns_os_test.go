package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

type withBase struct {
	*recordingDNS
	base dns.OSConfig
}

func (w withBase) GetBaseConfig() (dns.OSConfig, error) { return w.base, nil }
func (w withBase) SupportsSplitDNS() bool               { return true }

func TestDNSDirectServiceAddressUpstreams(t *testing.T) {
	upstreams := []netip.Addr{
		netip.MustParseAddr("100.100.100.100"),
		netip.MustParseAddr("fd7a:115c:a1e0::53"),
	}
	for _, tc := range []struct{ name, policy string }{
		{"without listener", ""},
		{"with listener", "[DNS]\nAddress = 10.9.0.53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := node{key.NewNode(), netip.MustParsePrefix("100.64.1.1/32"), 0}
			cfg := n.parse(t, "DNS = 100.100.100.100, fd7a:115c:a1e0::53", tc.policy)
			os := withBase{recordingDNS: new(recordingDNS)}
			e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{Tun: newTestStack(t, cfg), DNS: os})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(e.Close)
			if !slices.Equal(os.set.Nameservers, upstreams) {
				t.Fatalf("OS nameservers = %v, want %v", os.set.Nameservers, upstreams)
			}
		})
	}
}

func TestDNSBaseResolvers(t *testing.T) {
	owned := netip.MustParseAddr("10.9.0.53")
	upstream := netip.MustParseAddr("100.100.100.100")
	base := dns.OSConfig{
		Nameservers: []netip.Addr{owned, upstream},
		Resolvers: []*dnstype.Resolver{
			{Addr: "10.9.0.53"},
			{Addr: "10.9.0.53:53"},
			{Addr: "10.9.0.53:5353"},
			{Addr: "100.100.100.100"},
		},
	}
	wantNS, wantResolvers := slices.Clone(base.Nameservers), slices.Clone(base.Resolvers)
	n := node{key.NewNode(), netip.MustParsePrefix("100.64.1.1/32"), 0}
	cfg := n.parse(t, "", "[DNS]\nAddress = 10.9.0.53")
	os := withBase{new(recordingDNS), base}
	e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{Tun: newTestStack(t, cfg), DNS: os})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	filtered, err := e.dnsManager.GetBaseConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(filtered.Nameservers, wantNS[1:]) ||
		!slices.EqualFunc(filtered.Resolvers, wantResolvers[2:], (*dnstype.Resolver).Equal) {
		t.Fatalf("usable nameservers = %v, resolvers = %v", filtered.Nameservers, filtered.Resolvers)
	}
	if !slices.Equal(base.Nameservers, wantNS) || !slices.Equal(base.Resolvers, wantResolvers) {
		t.Fatalf("backend snapshot mutated: %v, %v", base.Nameservers, base.Resolvers)
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
