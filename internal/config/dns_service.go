package config

import (
	"net/netip"
	"slices"

	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/tsaddr"
)

// DNSServiceIPs returns the local resolver endpoints for the interface's
// address families when DNS policy can require the node's resolver.
func (cfg *Config) DNSServiceIPs() []netip.Addr {
	if len(cfg.DNS.Hosts)+len(cfg.DNS.Routes) == 0 &&
		!slices.ContainsFunc(cfg.Interface.DNS, publicdns.IPIsDoHOnlyServer) {
		return nil
	}
	var servers []netip.Addr
	for _, ip := range []netip.Addr{tsaddr.TailscaleServiceIP(), tsaddr.TailscaleServiceIPv6()} {
		if slices.ContainsFunc(cfg.Interface.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() == ip.Is4() }) {
			servers = append(servers, ip)
		}
	}
	return servers
}
