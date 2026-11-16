package provider

import (
	"fmt"
	"net"
	"sync"

	"tailscale.com/net/dns"
)

// providerDNS captures the manager's settings for the host to apply after
// startup. The base reader recovers OS settings without this tunnel.
type providerDNS struct {
	mu      sync.Mutex
	base    func() (dns.OSConfig, error)
	current dns.OSConfig
}

func (d *providerDNS) SetDNS(c dns.OSConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.base == nil {
		return net.ErrClosed
	}
	d.current = c
	return nil
}
func (d *providerDNS) SupportsSplitDNS() bool { return true }
func (d *providerDNS) GetBaseConfig() (dns.OSConfig, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.base == nil {
		return dns.OSConfig{}, net.ErrClosed
	}
	return d.base()
}
func (d *providerDNS) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current, d.base = dns.OSConfig{}, nil
	return nil
}

// ConfigureDNS selects manager-owned DNS for a prepared provider. The returned
// bootstrap settings create the interface without directing queries at an
// engine that has not started. base must exclude this tunnel's contribution.
func ConfigureDNS(h int32, base func() (dns.OSConfig, error)) (*Settings, error) {
	mu.Lock()
	defer mu.Unlock()
	if h == 0 || h != handle || eng != nil || resolver != nil {
		return nil, fmt.Errorf("handle %d is not prepared for DNS", h)
	}
	if len(cfg.Interface.DNSSearch) > 0 && len(cfg.Interface.DNS)+len(cfg.DNS.Hosts)+len(cfg.DNS.Routes) == 0 {
		return nil, fmt.Errorf("search-only DNS requires nameservers or local DNS policy on Apple")
	}
	resolver = &providerDNS{base: base}
	s := settings(cfg)
	s.DNSServers, s.DNSSearch = nil, nil
	return s, nil
}

// DNSSettings recompiles DNS against the current OS base and returns the
// complete network settings for the host's serialized settings application.
func DNSSettings(h int32) (*Settings, error) {
	mu.Lock()
	defer mu.Unlock()
	if h == 0 || h != handle || eng == nil || resolver == nil {
		return nil, fmt.Errorf("handle %d is not running with managed DNS", h)
	}
	if err := eng.RecompileDNS(); err != nil {
		return nil, err
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	s := settings(cfg)
	s.DNSServers, s.DNSSearch = nil, nil
	for _, ip := range resolver.current.Nameservers {
		s.DNSServers = append(s.DNSServers, ip.String())
	}
	for _, domain := range resolver.current.SearchDomains {
		s.DNSSearch = append(s.DNSSearch, domain.WithoutTrailingDot())
	}
	for _, domain := range resolver.current.MatchDomains {
		s.DNSMatchDomains = append(s.DNSMatchDomains, domain.WithoutTrailingDot())
	}
	return s, nil
}
