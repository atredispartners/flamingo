package flamingo

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnsTestServer spawns a DNS collector on a free UDP port after letting the
// caller adjust the configuration.
func dnsTestServer(t *testing.T, setup func(*ConfDNS)) (string, chan map[string]string, *ConfDNS) {
	t.Helper()

	rw := NewRecordWriter()
	got := make(chan map[string]string, 16)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		select {
		case got <- rec:
		default:
		}
		return nil
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	pc.Close()

	conf := NewConfDNS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = port
	conf.ResolveToIP = "10.9.8.7,fd00::7"
	conf.RecordWriter = rw
	if setup != nil {
		setup(conf)
	}
	if err := SpawnDNS(conf); err != nil {
		t.Fatalf("SpawnDNS: %s", err)
	}
	t.Cleanup(conf.Shutdown)

	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), got, conf
}

// dnsAsk sends one query and returns the reply.
func dnsAsk(t *testing.T, addr, name string, qtype uint16, edns bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	if edns {
		m.SetEdns0(1232, true)
	}
	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := cl.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s/%s: exchange: %s", dns.TypeToString[qtype], name, err)
	}
	return resp
}

// TestDNSRecordTypes walks every record type the collector answers.
func TestDNSRecordTypes(t *testing.T) {
	addr, _, _ := dnsTestServer(t, nil)

	t.Run("A", func(t *testing.T) {
		resp := dnsAsk(t, addr, "intranet.corp.local", dns.TypeA, false)
		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d, want 1: %v", len(resp.Answer), resp.Answer)
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
		}
		if !a.A.Equal(net.ParseIP("10.9.8.7")) {
			t.Errorf("A = %s, want 10.9.8.7", a.A)
		}
		if a.Hdr.Ttl != dnsDefaultTTL {
			t.Errorf("TTL = %d, want %d", a.Hdr.Ttl, dnsDefaultTTL)
		}
		if !resp.Authoritative {
			t.Error("the answer is not marked authoritative")
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		resp := dnsAsk(t, addr, "intranet.corp.local", dns.TypeAAAA, false)
		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d, want 1: %v", len(resp.Answer), resp.Answer)
		}
		aaaa, ok := resp.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatalf("answer is %T, want *dns.AAAA", resp.Answer[0])
		}
		if !aaaa.AAAA.Equal(net.ParseIP("fd00::7")) {
			t.Errorf("AAAA = %s, want fd00::7", aaaa.AAAA)
		}
	})

	t.Run("SOA", func(t *testing.T) {
		resp := dnsAsk(t, addr, "corp.local", dns.TypeSOA, false)
		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d: %v", len(resp.Answer), resp.Answer)
		}
		soa, ok := resp.Answer[0].(*dns.SOA)
		if !ok {
			t.Fatalf("answer is %T, want *dns.SOA", resp.Answer[0])
		}
		if soa.Ns != "win-flamingo.corp.local." {
			t.Errorf("SOA mname = %q", soa.Ns)
		}
		if soa.Mbox != "hostmaster.corp.local." {
			t.Errorf("SOA rname = %q", soa.Mbox)
		}
	})

	t.Run("MX", func(t *testing.T) {
		resp := dnsAsk(t, addr, "corp.local", dns.TypeMX, false)
		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d: %v", len(resp.Answer), resp.Answer)
		}
		mx, ok := resp.Answer[0].(*dns.MX)
		if !ok {
			t.Fatalf("answer is %T, want *dns.MX", resp.Answer[0])
		}
		if mx.Mx != "corp.local." {
			t.Errorf("MX target = %q", mx.Mx)
		}
		// Glue so the client does not need a second lookup.
		if len(resp.Extra) == 0 {
			t.Error("no glue addresses for the MX target")
		}
	})

	t.Run("TXT", func(t *testing.T) {
		resp := dnsAsk(t, addr, "corp.local", dns.TypeTXT, false)
		if len(resp.Answer) != 1 {
			t.Fatalf("answer count = %d: %v", len(resp.Answer), resp.Answer)
		}
		txt, ok := resp.Answer[0].(*dns.TXT)
		if !ok {
			t.Fatalf("answer is %T, want *dns.TXT", resp.Answer[0])
		}
		if len(txt.Txt) != 1 || txt.Txt[0] != dnsDefaultTXT {
			t.Errorf("TXT = %v, want %q", txt.Txt, dnsDefaultTXT)
		}
	})

	t.Run("ANY", func(t *testing.T) {
		resp := dnsAsk(t, addr, "corp.local", dns.TypeANY, false)
		var sawA, sawAAAA bool
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.A:
				sawA = true
			case *dns.AAAA:
				sawAAAA = true
			}
		}
		if !sawA || !sawAAAA {
			t.Errorf("ANY answered A=%t AAAA=%t: %v", sawA, sawAAAA, resp.Answer)
		}
	})

	t.Run("unsupported type is NOERROR and empty", func(t *testing.T) {
		resp := dnsAsk(t, addr, "corp.local", dns.TypeCAA, false)
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("answer = %v, want empty", resp.Answer)
		}
	})
}

// TestDNSSRVPortMapping checks that a service lookup is pointed at the
// flamingo listener for that service.
func TestDNSSRVPortMapping(t *testing.T) {
	addr, _, _ := dnsTestServer(t, nil)

	for _, tc := range []struct {
		name   string
		port   uint16
		target string
	}{
		{"_ldap._tcp.dc._msdcs.corp.local", 389, "win-flamingo.dc._msdcs.corp.local."},
		{"_kerberos._tcp.corp.local", 88, "win-flamingo.corp.local."},
		{"_kerberos._udp.corp.local", 88, "win-flamingo.corp.local."},
		{"_smb._tcp.corp.local", 445, "win-flamingo.corp.local."},
		{"_cifs._tcp.corp.local", 445, "win-flamingo.corp.local."},
		{"_ldaps._tcp.corp.local", 636, "win-flamingo.corp.local."},
		{"_gc._tcp.corp.local", 389, "win-flamingo.corp.local."},
		{"_mqtt._tcp.corp.local", 1883, "win-flamingo.corp.local."},
	} {
		resp := dnsAsk(t, addr, tc.name, dns.TypeSRV, false)
		if len(resp.Answer) != 1 {
			t.Errorf("%s: answer count = %d: %v", tc.name, len(resp.Answer), resp.Answer)
			continue
		}
		srv, ok := resp.Answer[0].(*dns.SRV)
		if !ok {
			t.Errorf("%s: answer is %T, want *dns.SRV", tc.name, resp.Answer[0])
			continue
		}
		if srv.Port != tc.port {
			t.Errorf("%s: port = %d, want %d", tc.name, srv.Port, tc.port)
		}
		if srv.Target != tc.target {
			t.Errorf("%s: target = %q, want %q", tc.name, srv.Target, tc.target)
		}
		// The target must come with glue, or the client has to resolve a
		// name we would then have to answer again.
		if len(resp.Extra) == 0 {
			t.Errorf("%s: no glue addresses for %q", tc.name, srv.Target)
		}
	}
}

// TestDNSSRVUnknownService checks that a service with no flamingo listener is
// not pointed anywhere, rather than at a port where nothing answers.
func TestDNSSRVUnknownService(t *testing.T) {
	addr, _, _ := dnsTestServer(t, nil)

	for _, name := range []string{
		"_nosuchservice._tcp.corp.local",
		"notaservice.corp.local",
		"_ldap",
	} {
		resp := dnsAsk(t, addr, name, dns.TypeSRV, false)
		if len(resp.Answer) != 0 {
			t.Errorf("%s: answer = %v, want empty", name, resp.Answer)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode = %s, want NOERROR", name, dns.RcodeToString[resp.Rcode])
		}
	}
}

// TestDNSEDNS0Echo checks that an OPT record in the query is answered with one
// in the reply, carrying the negotiated buffer size and the DO bit.
func TestDNSEDNS0Echo(t *testing.T) {
	addr, _, _ := dnsTestServer(t, nil)

	resp := dnsAsk(t, addr, "intranet.corp.local", dns.TypeA, true)
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT record in the reply to an EDNS0 query")
	}
	if opt.UDPSize() != 1232 {
		t.Errorf("OPT UDP size = %d, want 1232", opt.UDPSize())
	}
	if !opt.Do() {
		t.Error("the DO bit was not echoed")
	}

	// A query without EDNS0 must not gain an OPT record.
	resp = dnsAsk(t, addr, "intranet.corp.local", dns.TypeA, false)
	if resp.IsEdns0() != nil {
		t.Error("an OPT record was added to a reply to a plain query")
	}
}

// TestDNSResolveToIPUnchanged pins the behaviour the --dns-resolve-to flag has
// always had: one IPv4 address answers A queries, and no address at all leaves
// the listener a pure observer.
func TestDNSResolveToIPUnchanged(t *testing.T) {
	addr, _, _ := dnsTestServer(t, func(c *ConfDNS) {
		c.ResolveToIP = "192.0.2.10"
	})
	resp := dnsAsk(t, addr, "wpad.corp.local", dns.TypeA, false)
	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("answer = %v, want 192.0.2.10", resp.Answer[0])
	}
	// An address family with no configured target yields no answer rather
	// than a made-up one.
	resp = dnsAsk(t, addr, "wpad.corp.local", dns.TypeAAAA, false)
	if len(resp.Answer) != 0 {
		t.Errorf("AAAA answered without an IPv6 target: %v", resp.Answer)
	}

	noResolve, _, _ := dnsTestServer(t, func(c *ConfDNS) {
		c.ResolveToIP = ""
	})
	resp = dnsAsk(t, noResolve, "wpad.corp.local", dns.TypeA, false)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL with no resolve target",
			dns.RcodeToString[resp.Rcode])
	}
}

// TestDNSQueriesRecorded checks that every query is still logged, whatever the
// type, which is the listener's original job.
func TestDNSQueriesRecorded(t *testing.T) {
	addr, got, _ := dnsTestServer(t, nil)

	dnsAsk(t, addr, "_ldap._tcp.corp.local", dns.TypeSRV, false)
	select {
	case rec := <-got:
		if rec["_type"] != "access" || rec["_proto"] != "dns" {
			t.Fatalf("record = %v", rec)
		}
		if rec["questions"] != "SRV/_ldap._tcp.corp.local." {
			t.Errorf("questions = %q", rec["questions"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no access record")
	}
}

// TestDNSMalformed makes sure odd questions neither panic the handler nor hang
// the listener.
func TestDNSMalformed(t *testing.T) {
	addr, _, _ := dnsTestServer(t, nil)

	// Raw datagrams that are not well-formed DNS at all.
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()
	for _, junk := range [][]byte{
		{},
		{0x00},
		{0xff, 0xff, 0xff, 0xff},
		make([]byte, 512),
	} {
		if _, err := conn.Write(junk); err != nil {
			t.Fatalf("write: %s", err)
		}
	}

	// The listener must still answer afterwards.
	resp := dnsAsk(t, addr, "still.alive.local", dns.TypeA, false)
	if len(resp.Answer) != 1 {
		t.Fatalf("listener stopped answering: %v", resp)
	}

	// A question for the root, and for a class we do not serve.
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)
	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	if _, _, err := cl.Exchange(m, addr); err != nil {
		t.Errorf("root SOA query: %s", err)
	}

	m = new(dns.Msg)
	m.SetQuestion("corp.local.", dns.TypeA)
	m.Question[0].Qclass = dns.ClassCHAOS
	if _, _, err := cl.Exchange(m, addr); err != nil {
		t.Errorf("CHAOS class query: %s", err)
	}
}

// TestDNSSRVServiceSplit checks the owner-name split on its own, including the
// Active Directory forms that put extra labels between the protocol and the
// zone.
func TestDNSSRVServiceSplit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service string
		zone    string
		ok      bool
	}{
		{"_ldap._tcp.corp.local.", "_ldap", "corp.local.", true},
		{"_LDAP._TCP.CORP.LOCAL.", "_ldap", "corp.local.", true},
		{"_ldap._tcp.dc._msdcs.corp.local.", "_ldap", "dc._msdcs.corp.local.", true},
		{"_ldap._tcp.", "_ldap", ".", true},
		{"corp.local.", "", "", false},
		{"_ldap.", "", "", false},
		{".", "", "", false},
		{"", "", "", false},
	} {
		service, zone, ok := dnsSRVService(tc.name)
		if ok != tc.ok || service != tc.service || zone != tc.zone {
			t.Errorf("dnsSRVService(%q) = %q, %q, %t; want %q, %q, %t",
				tc.name, service, zone, ok, tc.service, tc.zone, tc.ok)
		}
	}
}
