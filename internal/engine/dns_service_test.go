package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/util/dnsname"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

func dnsQuestion(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	q := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET,
		}},
	}
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dnsExchange(t *testing.T, conn net.Conn, tcp bool, query []byte) dnsmessage.Message {
	t.Helper()
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if tcp {
		query = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	var n int
	if tcp {
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			t.Fatal(err)
		}
		n = int(binary.BigEndian.Uint16(buf[:2]))
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			t.Fatal(err)
		}
	} else {
		var err error
		n, err = conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
	}
	var answer dnsmessage.Message
	if err := answer.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if answer.ID != 42 || !answer.Response || answer.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("answer = %+v", answer)
	}
	return answer
}

func dnsDial(t *testing.T, n *testNode, ip netip.Addr, tcp bool) net.Conn {
	t.Helper()
	addr := netip.AddrPortFrom(ip, 53)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if tcp {
		c, err := n.stack.dialTCP(ctx, addr)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c, err := gonet.DialUDP(n.stack.s, nil, addrPointer(addr), protocol(ip))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func addrPointer(addr netip.AddrPort) *tcpip.FullAddress {
	out := fullAddr(addr)
	return &out
}

func dnsNode(t *testing.T, addr, extra string) *testNode {
	t.Helper()
	cfg := node{key.NewNode(), netip.MustParsePrefix(addr), 0}.parse(t, extra,
		"[DNS]\nHost = dns-test.headwire.test 192.0.2.53 2001:db8::53\n")
	n, err := startNode(t, cfg, tstest.WhileTestRunningLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return n
}

func TestDNSServiceFamiliesAndRestart(t *testing.T) {
	for _, tc := range []struct{ name, addr, extra string }{
		{"ipv4", "100.64.0.1/32", ""},
		{"ipv6", "fd00::1/128", ""},
		{"dual", "100.64.0.1/32", "Address = fd00::1/128\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for range 3 {
				n := dnsNode(t, tc.addr, tc.extra)
				cfg := n.state.Load().cfg
				for _, ip := range cfg.DNSServiceIPs() {
					if !slices.Contains(Routes(cfg), netip.PrefixFrom(ip, ip.BitLen())) {
						t.Fatalf("missing service route for %s", ip)
					}
					for _, tcp := range []bool{false, true} {
						for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
							answer := dnsExchange(t, dnsDial(t, n, ip, tcp), tcp,
								dnsQuestion(t, "dns-test.headwire.test.", typ))
							if len(answer.Answers) != 1 {
								t.Fatalf("answers = %+v", answer)
							}
							if typ == dnsmessage.TypeA && answer.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 53} {
								t.Fatal("incorrect A answer")
							}
							if typ == dnsmessage.TypeAAAA && netip.AddrFrom16(answer.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA).String() != "2001:db8::53" {
								t.Fatal("incorrect AAAA answer")
							}
						}
					}
				}
				idle := dnsDial(t, n, cfg.DNSServiceIPs()[0], true)
				done := make(chan struct{})
				go func() { n.Close(); close(done) }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("shutdown blocked on idle TCP")
				}
				idle.Close()
			}
		})
	}
}

func TestDNSServiceForwardingAndTCPRetry(t *testing.T) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	respond := func(b []byte) []byte {
		var q dnsmessage.Message
		if err := q.Unpack(b); err != nil {
			panic(err)
		}
		q.Response = true
		q.RecursionAvailable = true
		for range 80 {
			q.Answers = append(q.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 80}},
			})
		}
		out, err := q.Pack()
		if err != nil {
			panic(err)
		}
		return out
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(respond(buf[:n]), from)
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 65535)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(buf[:2]))
				if _, err := io.ReadFull(c, buf[:n]); err != nil {
					return
				}
				out := respond(buf[:n])
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
			}()
		}
	}()
	n := dnsNode(t, "100.64.0.1/32", "\nMTU = 576")
	if err := n.dnsManager.Set(dns.Config{DefaultResolvers: []*dnstype.Resolver{{Addr: tcp.Addr().String()}}}); err != nil {
		t.Fatal(err)
	}
	ip := n.dnsService.servers[0]
	query := dnsQuestion(t, "forwarded.example.", dnsmessage.TypeA)
	answer := dnsExchange(t, dnsDial(t, n, ip, false), false, query)
	if !answer.Truncated {
		t.Fatal("large UDP response did not request TCP retry")
	}
	answer = dnsExchange(t, dnsDial(t, n, ip, true), true, query)
	if answer.Truncated || len(answer.Answers) != 80 {
		t.Fatalf("TCP retry = %+v", answer)
	}
	// EDNS permits a full response, which must cross the small TUN MTU.
	var edns dnsmessage.Message
	if err := edns.Unpack(query); err != nil {
		t.Fatal(err)
	}
	edns.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{
		Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096,
	}, Body: &dnsmessage.OPTResource{}}}
	query, err = edns.Pack()
	if err != nil {
		t.Fatal(err)
	}
	answer = dnsExchange(t, dnsDial(t, n, ip, false), false, query)
	if answer.Truncated || len(answer.Answers) != 80 {
		t.Fatalf("fragmented UDP = %+v", answer)
	}
}

func TestDNSServicePeerBoundaryAndDefaultRoute(t *testing.T) {
	for _, tc := range []struct{ name, enabled, a, b, service, all string }{
		{"ipv4/hook", "true", "100.64.0.1/32", "100.64.0.2/32", "100.100.100.100", "0.0.0.0/0"},
		{"ipv4/no-hook", "false", "100.64.0.1/32", "100.64.0.2/32", "100.100.100.100", "0.0.0.0/0"},
		{"ipv6/hook", "true", "fd00::1/128", "fd00::2/128", "fd7a:115c:a1e0::53", "::/0"},
		{"ipv6/no-hook", "false", "fd00::1/128", "fd00::2/128", "fd7a:115c:a1e0::53", "::/0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TS_DEBUG_CONNECT_FAILURES", tc.enabled)
			a := node{key.NewNode(), netip.MustParsePrefix(tc.a), freePort(t)}
			b := node{key.NewNode(), netip.MustParsePrefix(tc.b), freePort(t)}
			ac := a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port))
			ac.Peers[0].AllowedIPs = append(ac.Peers[0].AllowedIPs, netip.PrefixFrom(netip.MustParseAddr(tc.service), netip.MustParseAddr(tc.service).BitLen()))
			bc := b.config(t, "", a, "")
			bc.DNS = config.DNS{Hosts: map[dnsname.FQDN][]netip.Addr{"dns-test.headwire.test.": {netip.MustParseAddr("192.0.2.53")}}}
			bc.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix(tc.all)}
			ea := startEcho(t, ac)
			eb := startEcho(t, bc)
			warm(t, ea.Engine, eb.Engine)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := dialRoundTripUntil(ctx, eb, netip.AddrPortFrom(a.addr.Addr(), testEchoPort)); err != nil {
				t.Fatal(err)
			}
			ip := netip.MustParseAddr(tc.service)
			if conn, err := eb.stack.dialTCP(ctx, netip.AddrPortFrom(ip, 80)); err == nil {
				conn.Close()
				t.Fatal("unsupported service port accepted a connection")
			} else if ctx.Err() != nil {
				t.Fatal("unsupported service port was not rejected locally")
			}
			query := dnsQuestion(t, "dns-test.headwire.test.", dnsmessage.TypeA)
			before := eb.peerStatus(a.priv.Public()).RxBytes
			c := dnsDial(t, ea, ip, false)
			defer c.Close()
			if _, err := c.Write(query); err != nil {
				t.Fatal(err)
			}
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := c.Read(make([]byte, 512)); err == nil {
				t.Fatal("peer queried local DNS")
			}
			if eb.peerStatus(a.priv.Public()).RxBytes <= before {
				t.Fatal("peer query did not cross WireGuard")
			}
			if answer := dnsExchange(t, dnsDial(t, eb, ip, false), false, query); len(answer.Answers) != 1 {
				t.Fatal(answer)
			}
			drop := eb.tun.PreFilterPacketInboundFromWireGuard
			if result := drop(&packet.Parsed{Dst: netip.AddrPortFrom(ip, 80)}, nil); result != filter.DropSilently {
				t.Fatal(result)
			}
		})
	}
}

func TestDNSServiceTCPLimitAndCancellation(t *testing.T) {
	n := dnsNode(t, "100.64.0.1/32",
		"Address = fd00::1/128\n")
	servers := n.dnsService.servers
	query := dnsQuestion(t, "dns-test.headwire.test.", dnsmessage.TypeA)
	var clients []net.Conn
	for i := range dnsTCPMaxSessions {
		c := dnsDial(t, n, servers[i%len(servers)], true)
		if answer := dnsExchange(t, c, true, query); len(answer.Answers) != 1 {
			t.Fatal("admitted TCP session did not answer")
		}
		clients = append(clients, c)
	}
	if got := len(n.dnsService.tcpSlots); got != dnsTCPMaxSessions {
		t.Fatalf("admitted %d sessions, want %d", got, dnsTCPMaxSessions)
	}
	for _, ip := range servers {
		c := dnsDial(t, n, ip, true)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		c.Close()
		if err == nil {
			t.Fatal("excess TCP session returned data")
		}
		if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
			t.Fatal("excess TCP session was left open")
		}
		if answer := dnsExchange(t, dnsDial(t, n, ip, false), false, query); len(answer.Answers) != 1 {
			t.Fatal("idle TCP sessions starved UDP")
		}
	}
	clients[0].Close()
	// Acquiring and returning a permit waits for the closed session to retire.
	select {
	case n.dnsService.tcpSlots <- struct{}{}:
		<-n.dnsService.tcpSlots
	case <-time.After(3 * time.Second):
		t.Fatal("closed TCP session retained its slot")
	}
	if answer := dnsExchange(t, dnsDial(t, n, servers[0], true), true, query); len(answer.Answers) != 1 {
		t.Fatal("replacement TCP session did not answer")
	}
	if got := len(n.dnsService.tcpSlots); got != dnsTCPMaxSessions {
		t.Fatalf("replacement left %d active sessions, want %d", got, dnsTCPMaxSessions)
	}
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not end idle sessions")
	}
	if got := len(n.dnsService.tcpSlots); got != 0 {
		t.Fatalf("shutdown retained %d session slots", got)
	}
}

type resetListener struct {
	net.Listener
	conns chan net.Conn
}

func (l resetListener) Accept() (net.Conn, error) {
	if c, ok := <-l.conns; ok {
		return c, nil
	}
	return nil, net.ErrClosed
}

type resetConn struct {
	net.Conn
	closed bool
}

func (c *resetConn) RemoteAddr() net.Addr { return nil }
func (c *resetConn) Close() error         { c.closed = true; return nil }

func TestDNSServiceTCPReset(t *testing.T) {
	n := dnsNode(t, "100.64.0.1/32", "")
	c := &resetConn{}
	l := resetListener{conns: make(chan net.Conn, 1)}
	l.conns <- c
	close(l.conns)
	n.dnsService.serveTCP(l)
	if !c.closed {
		t.Fatal("reset connection left open")
	}
}

func TestDNSServiceDisabled(t *testing.T) {
	cfg := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}.parse(t, "DNS = 192.0.2.53", "")
	n, err := startNode(t, cfg, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	if n.dnsService != nil || strings.Contains(fmt.Sprint(Routes(n.state.Load().cfg)), "100.100.100.100") {
		t.Fatal("direct DNS enabled the service")
	}
}

func TestDNSServiceCloseDuringForwarding(t *testing.T) {
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	received := make(chan error, 1)
	go func() { _, _, err := upstream.ReadFrom(make([]byte, 4096)); received <- err }()
	n := dnsNode(t, "100.64.0.1/32", "")
	if err := n.dnsManager.Set(dns.Config{DefaultResolvers: []*dnstype.Resolver{{Addr: upstream.LocalAddr().String()}}}); err != nil {
		t.Fatal(err)
	}
	c := dnsDial(t, n, n.dnsService.servers[0], false)
	defer c.Close()
	if _, err := c.Write(dnsQuestion(t, "pending.example.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive query")
	}
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown waited for upstream timeout")
	}
}

type blockedDNSDevice struct {
	tun.Device
	entered, closed      chan struct{}
	enterOnce, closeOnce sync.Once
}

func (d *blockedDNSDevice) Write([][]byte, int) (int, error) {
	d.enterOnce.Do(func() { close(d.entered) })
	<-d.closed
	return 0, net.ErrClosed
}

func (d *blockedDNSDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return d.Device.Close()
}

func TestDNSServiceCloseWithBlockedPacketDelivery(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	cfg := a.parse(t, "", "[DNS]\nHost = dns-test.headwire.test 192.0.2.53\n")
	device := &blockedDNSDevice{Device: newTestStack(t, cfg), entered: make(chan struct{}), closed: make(chan struct{})}
	e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{Tun: device})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	from := device.Device.(*testStack)
	addr := netip.MustParseAddrPort("100.100.100.100:53")
	c, err := gonet.DialUDP(from.s, nil, addrPointer(addr), protocol(addr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(dnsQuestion(t, "dns-test.headwire.test.", dnsmessage.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-device.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no response reached blocked TUN")
	}
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown blocked on packet delivery")
	}
}

func TestDNSPolicyAnswersAndReload(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	cfg := a.parse(t, "", "[DNS]\nHost = only4.example 192.0.2.53\nRoute = lab.example\n")
	n, err := startNode(t, cfg, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	for _, tc := range []struct {
		name    string
		typ     dnsmessage.Type
		rcode   dnsmessage.RCode
		answers int
	}{
		{"ONLY4.example.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, 1},
		{"only4.example.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, 0},
		{"child.only4.example.", dnsmessage.TypeA, dnsmessage.RCodeNameError, 0},
		{"missing.lab.example.", dnsmessage.TypeA, dnsmessage.RCodeNameError, 0},
	} {
		response, err := n.dnsManager.Query(context.Background(), dnsQuestion(t, tc.name, tc.typ), "udp",
			netip.MustParseAddrPort("100.64.0.1:40000"))
		if err != nil {
			t.Fatal(err)
		}
		var answer dnsmessage.Message
		if err := answer.Unpack(response); err != nil {
			t.Fatal(err)
		}
		if answer.RCode != tc.rcode || len(answer.Answers) != tc.answers {
			t.Fatalf("%s: %+v", tc.name, answer)
		}
	}
	before := n.state.Load()
	if err := n.Reload(a.parse(t, "", "[DNS]\nHost = only4.example 192.0.2.54\n")); err == nil || !strings.Contains(err.Error(), "[DNS]") {
		t.Fatalf("DNS reload = %v", err)
	}
	if n.state.Load() != before {
		t.Fatal("rejected DNS reload changed state")
	}
	answer := dnsExchange(t, dnsDial(t, n, netip.MustParseAddr("100.100.100.100"), false), false,
		dnsQuestion(t, "only4.example.", dnsmessage.TypeA))
	if answer.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 53} {
		t.Fatal(answer)
	}
}
