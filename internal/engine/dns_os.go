package engine

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
)

// managedDNS advertises the configured resolver addresses in place of the
// fixed service addresses the resolver manager emits, keeps them out of the
// base configuration it forwards to, and restores OS DNS before local packet
// delivery stops. Closing serializes with link-change reapplication and
// prevents later callbacks from taking over.
type managedDNS struct {
	mu      sync.Mutex
	os      dns.OSConfigurator
	servers []netip.Addr
}

func (m *managedDNS) SetDNS(cfg dns.OSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.os == nil {
		return net.ErrClosed
	}
	var nameservers []netip.Addr
	for _, ip := range cfg.Nameservers {
		if ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
			i := slices.IndexFunc(m.servers, func(s netip.Addr) bool { return s.Is4() == ip.Is4() })
			if i < 0 {
				continue
			}
			ip = m.servers[i]
		}
		nameservers = append(nameservers, ip)
	}
	cfg.Nameservers = nameservers
	return m.os.SetDNS(cfg)
}

func (m *managedDNS) SupportsSplitDNS() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.os != nil && m.os.SupportsSplitDNS()
}

func (m *managedDNS) GetBaseConfig() (dns.OSConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.os == nil {
		return dns.OSConfig{}, net.ErrClosed
	}
	cfg, err := m.os.GetBaseConfig()
	cfg.Nameservers = slices.DeleteFunc(cfg.Nameservers, func(ip netip.Addr) bool {
		return slices.Contains(m.servers, ip.Unmap())
	})
	cfg.Resolvers = slices.DeleteFunc(cfg.Resolvers, func(r *dnstype.Resolver) bool {
		ap, err := netip.ParseAddrPort(r.Addr)
		return err == nil && slices.Contains(m.servers, ap.Addr().Unmap())
	})
	return cfg, err
}

func (m *managedDNS) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.os == nil {
		return nil
	}
	defer func() { m.os = nil }()
	return m.os.Close()
}

// RecompileDNS refreshes the resolver policy after the host's base DNS changes.
func (e *Engine) RecompileDNS() error { return e.dnsManager.RecompileDNSConfig() }
