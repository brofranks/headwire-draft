package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"

	"brof.dev/headwire/internal/config"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	gvheader "gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack/gro"
)

// dnsQueueLen bounds responses awaiting delivery to the TUN. The link drops
// a response when it is full, and the client retries.
const dnsQueueLen = 256

const dnsTCPMaxSessions = 256

// dnsConfig translates static DNS policy for the engine's resolver manager.
func dnsConfig(cfg *config.Config) *dns.Config {
	resolvers := func(addrs []netip.Addr) []*dnstype.Resolver {
		rs := []*dnstype.Resolver{}
		for _, a := range addrs {
			rs = append(rs, &dnstype.Resolver{Addr: a.String()})
		}
		return rs
	}
	c := &dns.Config{
		SearchDomains: cfg.Interface.DNSSearch,
		Hosts:         cfg.DNS.Hosts,
		Routes:        map[dnsname.FQDN][]*dnstype.Resolver{},
		OnlyIPv6:      !slices.ContainsFunc(cfg.Interface.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() }),
	}
	if len(cfg.Interface.DNS) > 0 {
		c.DefaultResolvers = resolvers(cfg.Interface.DNS)
	}
	for suffix, addrs := range cfg.DNS.Routes {
		c.Routes[suffix] = resolvers(addrs)
	}
	for host, addrs := range cfg.DNS.Hosts {
		c.Routes[host] = nil
		for _, ip := range addrs {
			ptr := reverseDNSName(ip)
			// An explicit reverse route already delivers the PTR to the
			// resolver and controls forwarding for other record types.
			if !hasDNSRoute(cfg.DNS.Routes, ptr) {
				c.Routes[ptr] = nil
			}
		}
	}
	return c
}

func hasDNSRoute(routes map[dnsname.FQDN][]netip.Addr, name dnsname.FQDN) bool {
	for ; name != ""; name = name.Parent() {
		if _, ok := routes[name]; ok {
			return true
		}
	}
	return false
}

// reverseDNSName returns the PTR owner for the address as stored in Hosts.
func reverseDNSName(ip netip.Addr) dnsname.FQDN {
	if ip.Is4() {
		b := ip.As4()
		return dnsname.FQDN(fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0]))
	}
	b := ip.As16()
	const hex = "0123456789abcdef"
	name := make([]byte, 0, 64+len("ip6.arpa."))
	for i := len(b) - 1; i >= 0; i-- {
		name = append(name, hex[b[i]&15], '.', hex[b[i]>>4], '.')
	}
	return dnsname.FQDN(append(name, "ip6.arpa."...))
}

// dnsService terminates virtual DNS traffic from the host. Its stack owns
// only the service addresses, and no decrypted peer packet enters it.
type dnsService struct {
	manager  *dns.Manager
	logf     logger.Logf
	ctx      context.Context
	cancel   context.CancelFunc
	stack    *stack.Stack
	link     *channel.Endpoint
	servers  []netip.Addr
	udp      []*gonet.UDPConn
	tcp      []net.Listener
	tcpSlots chan struct{}
	workers  sync.WaitGroup
}

func dnsProtocol(ip netip.Addr) tcpip.NetworkProtocolNumber {
	if ip.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func newDNSService(
	manager *dns.Manager,
	tun *tstun.Wrapper,
	servers []netip.Addr,
	mtu int,
	logf logger.Logf,
) (_ *dnsService, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &dnsService{
		manager:  manager,
		logf:     logf,
		ctx:      ctx,
		cancel:   cancel,
		servers:  servers,
		tcpSlots: make(chan struct{}, dnsTCPMaxSessions),
		stack: stack.New(stack.Options{
			NetworkProtocols: []stack.NetworkProtocolFactory{
				ipv4.NewProtocol,
				ipv6.NewProtocol,
			},
			TransportProtocols: []stack.TransportProtocolFactory{
				tcp.NewProtocol,
				udp.NewProtocol,
			},
		}),
		link: channel.New(dnsQueueLen, uint32(mtu), ""),
	}
	defer func() {
		if err != nil {
			s.stop()
			s.wait()
		}
	}()
	if problem := s.stack.CreateNIC(1, s.link); problem != nil {
		return nil, fmt.Errorf("DNS NIC: %s", problem)
	}
	s.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: gvheader.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: gvheader.IPv6EmptySubnet,
			NIC:         1,
		},
	})
	for _, ip := range servers {
		if problem := s.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          dnsProtocol(ip),
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{}); problem != nil {
			return nil, fmt.Errorf("DNS address %s: %s", ip, problem)
		}
		addr := tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(ip.AsSlice()),
			Port: 53,
		}
		udpConn, err := gonet.DialUDP(s.stack, &addr, nil, dnsProtocol(ip))
		if err != nil {
			return nil, fmt.Errorf("DNS UDP %s: %w", ip, err)
		}
		s.udp = append(s.udp, udpConn)
		tcpListener, err := gonet.ListenTCP(s.stack, addr, dnsProtocol(ip))
		if err != nil {
			return nil, fmt.Errorf("DNS TCP %s: %w", ip, err)
		}
		s.tcp = append(s.tcp, tcpListener)
	}
	for _, conn := range s.udp {
		s.workers.Go(func() { s.serveUDP(conn) })
	}
	for _, listener := range s.tcp {
		s.workers.Go(func() { s.serveTCP(listener) })
	}
	s.workers.Go(func() {
		for {
			pkt := s.link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			err := tun.InjectInboundCopy(view.AsSlice())
			view.Release()
			pkt.DecRef()
			if err != nil && ctx.Err() == nil {
				logf("DNS response injection: %v", err)
			}
		}
	})
	tun.PreFilterPacketOutboundToWireGuardNetstackIntercept = func(
		p *packet.Parsed, t *tstun.Wrapper, g *gro.GRO,
	) (filter.Response, *gro.GRO) {
		if !slices.Contains(servers, p.Dst.Addr()) {
			return filter.Accept, g
		}
		if ctx.Err() == nil {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(slices.Clone(p.Buffer())),
			})
			s.link.InjectInbound(dnsProtocol(p.Dst.Addr()), pkt)
			pkt.DecRef()
		}
		return filter.DropSilently, g
	}
	// The engine may install an inbound hook, which this one wraps.
	previousInbound := tun.PreFilterPacketInboundFromWireGuard
	tun.PreFilterPacketInboundFromWireGuard = func(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
		if slices.Contains(servers, p.Dst.Addr()) {
			return filter.DropSilently
		}
		if previousInbound != nil {
			return previousInbound(p, t)
		}
		return filter.Accept
	}
	return s, nil
}

func (s *dnsService) serveUDP(conn *gonet.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if s.ctx.Err() == nil {
				s.logf("DNS UDP read: %v", err)
			}
			return
		}
		query := slices.Clone(buf[:n])
		// The manager bounds concurrent queries and rejects the excess.
		s.workers.Go(func() {
			answer, err := s.manager.Query(s.ctx, query, "udp", from.(*net.UDPAddr).AddrPort())
			if err != nil {
				if s.ctx.Err() == nil {
					s.logf("DNS query: %v", err)
				}
				return
			}
			if _, err := conn.WriteTo(answer, from); err != nil && s.ctx.Err() == nil {
				s.logf("DNS UDP reply: %v", err)
			}
		})
	}
}

func (s *dnsService) serveTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil {
				s.logf("DNS TCP accept: %v", err)
			}
			return
		}
		// RemoteAddr is nil once the client has reset the connection.
		from, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}
		select {
		case s.tcpSlots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.workers.Go(func() {
			defer func() { <-s.tcpSlots }()
			defer conn.Close()
			s.manager.HandleTCPConn(conn, from.AddrPort())
		})
	}
}

// stop cancels DNS work before the engine closes the resolver and TUN.
// Closing the stack aborts accepted TCP sessions.
func (s *dnsService) stop() {
	s.cancel()
	for _, conn := range s.udp {
		conn.Close()
	}
	for _, listener := range s.tcp {
		listener.Close()
	}
	s.stack.Close()
}

// wait joins packet delivery after closing the TUN unblocks pending writes.
// The stack closes its link when it removes the NIC.
func (s *dnsService) wait() {
	s.workers.Wait()
	s.stack.Wait()
}
