package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	"tailscale.com/util/dnsname"
)

// DNS is the [DNS] section: the records the node's resolver serves. Hosts
// maps a lowercase FQDN to its addresses. Routes maps a domain suffix to the
// resolvers answering names under it, and an empty list makes the node
// authoritative for the suffix, so a name under it without a Host record does
// not exist. Both maps are nil when the section is absent.
type DNS struct {
	Hosts  map[dnsname.FQDN][]netip.Addr
	Routes map[dnsname.FQDN][]netip.Addr
}

// parseDNS reads Host and Route records, one per line, each a name or
// suffix followed by addresses separated by commas or whitespace.
func parseDNS(s *section, d *DNS) error {
	if err := s.checkKnownKeys("Host", "Route"); err != nil {
		return err
	}
	d.Hosts, d.Routes = map[dnsname.FQDN][]netip.Addr{}, map[dnsname.FQDN][]netip.Addr{}
	routeLines := map[dnsname.FQDN]int{}
	for _, e := range s.entries {
		fields := strings.FieldsFunc(e.value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
		host := strings.EqualFold(e.key, "Host")
		if len(fields) == 0 || host && len(fields) == 1 {
			return fmt.Errorf("line %d: %s: expected a name followed by addresses", e.line, e.key)
		}
		// The resolver lowercases a query before looking it up.
		name, err := dnsname.ToFQDN(strings.ToLower(fields[0]))
		if _, isAddr := netip.ParseAddr(fields[0]); err != nil || isAddr == nil || name == "." {
			return fmt.Errorf("line %d: %s: invalid name %q", e.line, e.key, fields[0])
		}
		addrs := []netip.Addr{}
		for _, f := range fields[1:] {
			addr, err := netip.ParseAddr(f)
			if err != nil {
				return fmt.Errorf("line %d: %s: invalid address %q", e.line, e.key, f)
			}
			if addr.Zone() != "" {
				return fmt.Errorf("line %d: %s: zone is only valid in an Endpoint, not a record", e.line, e.key)
			}
			addrs = append(addrs, addr)
		}
		if !host {
			if _, dup := d.Routes[name]; dup {
				return fmt.Errorf("line %d: Route: duplicate suffix %s", e.line, name.WithoutTrailingDot())
			}
			d.Routes[name], routeLines[name] = addrs, e.line
			continue
		}
		for _, addr := range addrs {
			if slices.Contains(d.Hosts[name], addr) {
				return fmt.Errorf("line %d: Host: duplicate address %s for %s", e.line, addr, name.WithoutTrailingDot())
			}
			d.Hosts[name] = append(d.Hosts[name], addr)
		}
	}
	// The resolver answers a Host's name and everything beneath it from its
	// records, so a Route there could never forward.
	for suffix, line := range routeLines {
		for host := range d.Hosts {
			if host.Contains(suffix) {
				return fmt.Errorf("line %d: Route: %s is a Host name or lies beneath one, which the resolver answers itself", line, suffix.WithoutTrailingDot())
			}
		}
	}
	for suffix, resolvers := range d.Routes {
		if len(resolvers) == 0 {
			continue
		}
		for authority, upstreams := range d.Routes {
			if len(upstreams) == 0 && authority.Contains(suffix) {
				return fmt.Errorf("line %d: Route: %s lies beneath authoritative suffix %s", routeLines[suffix], suffix.WithoutTrailingDot(), authority.WithoutTrailingDot())
			}
		}
	}
	return nil
}
