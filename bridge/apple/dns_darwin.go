package main

/*
#include <netdb.h>
#include <resolv.h>
#include <sys/socket.h>

static int hw_base_server(res_state state, int index, char *host, size_t hostlen, char *port, size_t portlen) {
    union res_sockaddr_union servers[MAXNS];
    int count = res_getservers(state, servers, MAXNS);
    if (index >= count) return 0;
    struct sockaddr *addr = (struct sockaddr *)&servers[index];
    int err = getnameinfo(addr, addr->sa_len, host, (socklen_t)hostlen, port, (socklen_t)portlen,
        NI_NUMERICHOST | NI_NUMERICSERV);
    return err ? -1 : 1;
}
*/
import "C"

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"tailscale.com/net/dns"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

// baseDNS reads the native resolver configuration without retaining a startup
// snapshot. The engine removes the tunnel's own resolver from the result.
func baseDNS() (dns.OSConfig, error) {
	if runtime.GOOS == "darwin" {
		osDNS, err := dns.NewOSConfigurator(logf, nil, nil, nil, nil, "")
		if err != nil {
			return dns.OSConfig{}, err
		}
		return osDNS.GetBaseConfig()
	}
	var state C.struct___res_state
	if C.res_ninit(&state) != 0 {
		return dns.OSConfig{}, fmt.Errorf("read underlying DNS configuration")
	}
	defer C.res_ndestroy(&state)
	var cfg dns.OSConfig
	for i := range int(C.MAXNS) {
		var host [C.NI_MAXHOST]C.char
		var port [C.NI_MAXSERV]C.char
		switch C.hw_base_server(&state, C.int(i), &host[0], C.size_t(len(host)), &port[0], C.size_t(len(port))) {
		case 0:
			continue
		case -1:
			return dns.OSConfig{}, fmt.Errorf("read underlying DNS server %d", i)
		}
		addr, err := netip.ParseAddr(C.GoString(&host[0]))
		if err != nil {
			return dns.OSConfig{}, err
		}
		cfg.Resolvers = append(cfg.Resolvers, &dnstype.Resolver{Addr: net.JoinHostPort(addr.String(), C.GoString(&port[0]))})
	}
	for _, search := range state.dnsrch {
		if search == nil {
			break
		}
		domain, err := dnsname.ToFQDN(C.GoString(search))
		if err != nil {
			return dns.OSConfig{}, err
		}
		cfg.SearchDomains = append(cfg.SearchDomains, domain)
	}
	if len(cfg.Resolvers) == 0 {
		return dns.OSConfig{}, dns.ErrGetBaseConfigNoResolvers
	}
	return cfg, nil
}
