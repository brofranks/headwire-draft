package provider

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"

	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/dns"
	"tailscale.com/types/key"
)

func TestManagedDNSSettings(t *testing.T) {
	const host = "Host = host.example 192.0.2.1\n"
	const ptr4 = "1.2.0.192.in-addr.arpa"
	const ptr6 = "4.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	const dual = "100.64.0.1/32, fd00::1/128"
	routeServer := "192.0.2.53"
	if runtime.GOOS == "windows" {
		// Windows sends split queries through the local listener for WSL.
		routeServer = "100.64.0.53"
	}
	for _, tc := range []struct {
		name, addresses, policy string
		servers, match          []string
	}{
		{"none", "100.64.0.1/32", "", nil, nil},
		{"direct", "100.64.0.1/32", "DNS = 192.0.2.53\n", []string{"192.0.2.53"}, nil},
		{
			"host", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\n" + host,
			[]string{"100.64.0.53"}, []string{ptr4, "host.example"},
		},
		{
			"host6", "fd00::1/128", "[DNS]\nAddress = fd00::53\n" + host,
			[]string{"fd00::53"}, []string{ptr4, "host.example"},
		},
		{
			"dual", dual, "[DNS]\nAddress = 100.64.0.53, fd00::53\n" + host + "Host = host.example 2001:db8::54\n",
			[]string{"100.64.0.53", "fd00::53"}, []string{ptr4, ptr6, "host.example"},
		},
		{
			"dual IPv6 listener", dual, "[DNS]\nAddress = fd00::53\n" + host,
			[]string{"fd00::53"}, []string{ptr4, "host.example"},
		},
		{
			"route", "100.64.0.1/32", "[DNS]\nAddress = 100.64.0.53\nRoute = corp.example 192.0.2.53\n",
			[]string{routeServer}, []string{"corp.example"},
		},
		{
			"proxy", "100.64.0.1/32", "DNS = 192.0.2.53\n[DNS]\nAddress = 100.64.0.53\n" + host,
			[]string{"100.64.0.53"}, nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := config.Parse([]byte("[Interface]\nPrivateKey = " + config.EncodeKey(key.NewNode().Raw32()) + "\nAddress = " + tc.addresses + "\n" + tc.policy))
			if err != nil {
				t.Fatal(err)
			}
			h, _, err := Prepare(c)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { Stop(h, nil) })
			bootstrap, err := ConfigureDNS(h, func() (dns.OSConfig, error) {
				return dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.54")}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(bootstrap.DNSServers)+len(bootstrap.DNSSearch)+len(bootstrap.DNSMatchDomains) != 0 {
				t.Fatal(bootstrap)
			}
			if _, err := DNSSettings(h); err == nil {
				t.Fatal("DNS settings before Start")
			}
			if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf, nil); err != nil {
				t.Fatal(err)
			}
			settings, err := DNSSettings(h)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(settings.DNSServers, tc.servers) || !reflect.DeepEqual(settings.DNSMatchDomains, tc.match) {
				t.Fatalf("DNS = %+v, want servers %v and match %v", settings, tc.servers, tc.match)
			}
		})
	}
}

func TestProviderDNSBaseRefresh(t *testing.T) {
	var failed atomic.Bool
	want := errors.New("base DNS read failed")
	d := &providerDNS{base: func() (dns.OSConfig, error) {
		if failed.Load() {
			return dns.OSConfig{}, want
		}
		return dns.OSConfig{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.54")}}, nil
	}}
	first, err := d.GetBaseConfig()
	if err != nil || first.Nameservers[0].String() != "192.0.2.54" {
		t.Fatalf("base = %v, %v", first, err)
	}
	failed.Store(true)
	if _, err := d.GetBaseConfig(); !errors.Is(err, want) {
		t.Fatalf("fresh base read = %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDNS(first); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late update = %v", err)
	}
}

func TestProviderRejectsSearchOnlyDNS(t *testing.T) {
	for _, addresses := range []string{"100.64.0.1/32", "fd00::1/128", "100.64.0.1/32, fd00::1/128"} {
		c, err := config.Parse([]byte("[Interface]\nPrivateKey = " + config.EncodeKey(key.NewNode().Raw32()) + "\nAddress = " + addresses + "\nDNS = corp.example\n"))
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := Prepare(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ConfigureDNS(h, nil)
		if err == nil || err.Error() != "search-only DNS requires nameservers or local DNS policy on Apple" {
			t.Fatalf("search-only: %v", err)
		}
		if !Stop(h, nil) {
			t.Fatal("failed preparation retained admission")
		}
	}
}
