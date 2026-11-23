package config

import (
	"net/netip"
	"slices"

	"tailscale.com/net/dns/publicdns"
)

// DNSServiceIPs returns the addresses where the node's resolver listens.
func (cfg *Config) DNSServiceIPs() []netip.Addr { return cfg.DNS.Addresses }

// needsDNSService reports whether DNS policy can require the node's resolver:
// local records or routes, or a default nameserver reachable only over DoH.
func (cfg *Config) needsDNSService() bool {
	return len(cfg.DNS.Hosts)+len(cfg.DNS.Routes) > 0 ||
		slices.ContainsFunc(cfg.Interface.DNS, publicdns.IPIsDoHOnlyServer)
}
