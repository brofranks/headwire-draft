package engine

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
)

// managedDNS keeps advertised virtual endpoints within the configured families
// and restores OS DNS before local packet delivery stops. Closing serializes
// with link-change reapplication and prevents later callbacks from taking over.
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
	cfg.Nameservers = slices.DeleteFunc(slices.Clone(cfg.Nameservers), func(ip netip.Addr) bool {
		return (ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6()) && !slices.Contains(m.servers, ip)
	})
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
	return m.os.GetBaseConfig()
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
