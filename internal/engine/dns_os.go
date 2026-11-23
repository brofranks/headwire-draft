package engine

import (
	"net"
	"sync"

	"tailscale.com/net/dns"
)

// managedDNS serializes OS DNS updates with restoration before local packet
// delivery stops. Closing prevents later link-change callbacks from taking over.
type managedDNS struct {
	mu sync.Mutex
	os dns.OSConfigurator
}

func (m *managedDNS) SetDNS(cfg dns.OSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.os == nil {
		return net.ErrClosed
	}
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
