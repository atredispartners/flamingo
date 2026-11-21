package flamingo

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var dnsTypeMap = map[uint16]string{
	0:     "None",
	1:     "A",
	2:     "NS",
	3:     "MD",
	4:     "MF",
	5:     "CNAME",
	6:     "SOA",
	7:     "MB",
	8:     "MG",
	9:     "MR",
	10:    "NULL",
	12:    "PTR",
	13:    "HINFO",
	14:    "MINFO",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	19:    "X25",
	20:    "ISDN",
	21:    "RT",
	23:    "NSAPPTR",
	24:    "SIG",
	25:    "KEY",
	26:    "PX",
	27:    "GPOS",
	28:    "AAAA",
	29:    "LOC",
	30:    "NXT",
	31:    "EID",
	32:    "NIMLOC",
	33:    "SRV",
	34:    "ATMA",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	39:    "DNAME",
	41:    "OPT",
	42:    "APL",
	43:    "DS",
	44:    "SSHFP",
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",
	55:    "HIP",
	56:    "NINFO",
	57:    "RKEY",
	58:    "TALINK",
	59:    "CDS",
	60:    "CDNSKEY",
	61:    "OPENPGPKEY",
	62:    "CSYNC",
	99:    "SPF",
	100:   "UINFO",
	101:   "UID",
	102:   "GID",
	103:   "UNSPEC",
	104:   "NID",
	105:   "L32",
	106:   "L64",
	107:   "LP",
	108:   "EUI48",
	109:   "EUI64",
	256:   "URI",
	257:   "CAA",
	258:   "AVC",
	249:   "TKEY",
	250:   "TSIG",
	251:   "IXFR",
	252:   "AXFR",
	253:   "MAILB",
	254:   "MAILA",
	255:   "ANY",
	32768: "TA",
	32769: "DLV",
	65535: "Reserved",
}

// DNS answer defaults.
const (
	// dnsDefaultTTL is short enough that a victim re-asks often and long
	// enough that a single lookup is not repeated on every connection.
	dnsDefaultTTL = 30

	// dnsDefaultUDPSize is the pre-EDNS0 UDP answer limit. A larger answer
	// is truncated so the client retries over TCP rather than receiving a
	// malformed datagram.
	dnsDefaultUDPSize = 512

	// dnsMaxUDPSize caps the advertised EDNS0 buffer a client can talk us
	// into using.
	dnsMaxUDPSize = 4096

	// dnsDefaultTXT is the TXT value handed out when none is configured.
	// It says nothing about the host and is valid wherever a TXT record is
	// legal.
	dnsDefaultTXT = "v=spf1 -all"
)

// dnsSRVPorts maps an SRV service label to the port a flamingo listener is
// expected to be on, so a client looking up a service record is pointed at a
// collector rather than at the real thing. A service that is not in this table
// is not answered at all: an SRV record naming a port where nothing listens
// only wastes the client's time, and port 0 would actively tell it the service
// does not exist.
var dnsSRVPorts = map[string]uint16{
	// Active Directory. _gc is the global catalog, which speaks LDAP; it is
	// pointed at the LDAP collector rather than at 3268, where flamingo
	// does not listen.
	"_ldap":             389,
	"_ldaps":            636,
	"_gc":               389,
	"_kerberos":         88,
	"_kerberos-master":  88,
	"_kerberos-adm":     88,
	"_kpasswd":          88,
	"_smb":              445,
	"_cifs":             445,
	"_msdcs":            389,
	"_wsman":            5985,
	"_winrm":            5985,
	"_vmware-view":      443,
	"_http":             80,
	"_https":            443,
	"_ftp":              21,
	"_ssh":              22,
	"_smtp":             25,
	"_submission":       587,
	"_imap":             143,
	"_imaps":            993,
	"_pop3":             110,
	"_pop3s":            995,
	"_sip":              5060,
	"_sips":             5061,
	"_mssql":            1433,
	"_mysql":            3306,
	"_postgresql":       5432,
	"_mongodb":          27017,
	"_amqp":             5672,
	"_mqtt":             1883,
	"_redis":            6379,
	"_vnc":              5900,
	"_rdp":              3389,
	"_telnet":           23,
	"_snmp":             161,
	"_x-puppet":         8140,
	"_nfs":              2049,
	"_ldap-admin":       389,
	"_microsoft-ds":     445,
	"_netbios-ssn":      139,
	"_ms-sql-s":         1433,
	"_ms-wbt-server":    3389,
	"_ms-sql-m":         1434,
	"_domain":           53,
	"_autodiscover":     443,
	"_caldav":           80,
	"_caldavs":          443,
	"_carddav":          80,
	"_carddavs":         443,
	"_sipfederationtls": 5061,
}

// ConfDNS describes the configuration of the dns service
type ConfDNS struct {
	BindPort uint16
	BindHost string
	// Network only supports UDP for now.
	Network string

	// ResolveToIP is the address every answer points at. It accepts a
	// comma-separated list so one flag can supply both an IPv4 address for
	// A answers and an IPv6 address for AAAA answers. Empty leaves the
	// listener a pure observer: queries are logged and refused, which is
	// what flamingo has always done without this set.
	ResolveToIP string

	// TTL is the TTL on every answer. Zero means dnsDefaultTTL.
	TTL uint32

	// TXTValue is the string returned for TXT queries. Empty means
	// dnsDefaultTXT.
	TXTValue string

	// ServerHost is the host label used in SOA and SRV targets. Empty
	// derives it from the shared NTLM server identity, so one host name
	// shows up across every listener.
	ServerHost string

	RecordWriter *RecordWriter
	shutdown     bool
	server       *dns.Server
	m            sync.Mutex
}

// ttl returns the configured answer TTL.
func (c *ConfDNS) ttl() uint32 {
	if c.TTL != 0 {
		return c.TTL
	}
	return dnsDefaultTTL
}

// txtValue returns the configured TXT string.
func (c *ConfDNS) txtValue() string {
	if c.TXTValue != "" {
		return c.TXTValue
	}
	return dnsDefaultTXT
}

// serverHost returns the single host label used in SOA and SRV targets.
func (c *ConfDNS) serverHost() string {
	host := c.ServerHost
	if host == "" {
		host = NTLMConf.DNSComputerName
	}
	if host == "" {
		host = "ns"
	}
	// Only the first label is usable here; the zone supplies the rest.
	return strings.ToLower(strings.SplitN(strings.Trim(host, "."), ".", 2)[0])
}

// resolveTargets splits ResolveToIP into the IPv4 and IPv6 addresses answers
// point at. Anything unparseable is ignored rather than guessed at.
func (c *ConfDNS) resolveTargets() (v4 []net.IP, v6 []net.IP) {
	for _, part := range strings.Split(c.ResolveToIP, ",") {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
			continue
		}
		v6 = append(v6, ip)
	}
	return v4, v6
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfDNS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfDNS) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	c.shutdown = true
	c.server.Shutdown()
}

// ServeDNS handles DNS requests
func (c *ConfDNS) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	remoteAddr := w.RemoteAddr()
	questions := []string{}
	for _, q := range req.Question {
		qtype := dnsTypeMap[q.Qtype]
		if qtype == "" {
			qtype = fmt.Sprintf("%d", q.Qtype)
		}
		questions = append(questions, fmt.Sprintf("%s/%s", qtype, q.Name))
	}

	if len(questions) > 0 {
		c.RecordWriter.Record(
			"access",
			"dns",
			remoteAddr.String(),
			map[string]string{
				"_server":   fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
				"questions": strings.Join(questions, " "),
			},
		)
	}

	v4, v6 := c.resolveTargets()
	if (len(v4) == 0 && len(v6) == 0) || len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true

	q := req.Question[0]
	if q.Qclass != dns.ClassINET && q.Qclass != dns.ClassANY {
		dns.HandleFailed(w, req)
		return
	}
	m.Answer, m.Extra = c.dnsAnswer(q, v4, v6)

	// Echo EDNS0 so a modern client is not confused by a reply that drops
	// the OPT record it sent, and honour the buffer size it advertised.
	udpSize := dnsDefaultUDPSize
	if opt := req.IsEdns0(); opt != nil {
		size := int(opt.UDPSize())
		if size < dns.MinMsgSize {
			size = dns.MinMsgSize
		}
		if size > dnsMaxUDPSize {
			size = dnsMaxUDPSize
		}
		udpSize = size
		m.SetEdns0(uint16(size), opt.Do())
	}
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		m.Truncate(udpSize)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Debugf("dns: failed to answer %s: %s", remoteAddr, err)
	}
}

// dnsAnswer builds the ANSWER and ADDITIONAL sections for one question. An
// unsupported type yields an empty NOERROR rather than a failure, which stops
// the client falling back to a DNS server that would answer honestly.
func (c *ConfDNS) dnsAnswer(q dns.Question, v4, v6 []net.IP) (answer, extra []dns.RR) {
	name := q.Name
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: c.ttl()}
	}

	addrs := func(n string) []dns.RR {
		var out []dns.RR
		h := func(rrtype uint16) dns.RR_Header {
			return dns.RR_Header{Name: n, Rrtype: rrtype, Class: dns.ClassINET, Ttl: c.ttl()}
		}
		for _, ip := range v4 {
			out = append(out, &dns.A{Hdr: h(dns.TypeA), A: ip})
		}
		for _, ip := range v6 {
			out = append(out, &dns.AAAA{Hdr: h(dns.TypeAAAA), AAAA: ip})
		}
		return out
	}

	switch q.Qtype {
	case dns.TypeA:
		for _, ip := range v4 {
			answer = append(answer, &dns.A{Hdr: hdr(dns.TypeA), A: ip})
		}

	case dns.TypeAAAA:
		for _, ip := range v6 {
			answer = append(answer, &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: ip})
		}

	case dns.TypeANY:
		answer = addrs(name)
		answer = append(answer, c.dnsTXT(hdr(dns.TypeTXT)))

	case dns.TypeTXT:
		answer = append(answer, c.dnsTXT(hdr(dns.TypeTXT)))

	case dns.TypeSOA:
		answer = append(answer, c.dnsSOA(hdr(dns.TypeSOA), name))

	case dns.TypeMX:
		// The mail exchanger is the queried name itself, which this
		// listener also answers with an address, so a mail client ends up
		// on flamingo's SMTP collector.
		answer = append(answer, &dns.MX{Hdr: hdr(dns.TypeMX), Preference: 10, Mx: name})
		extra = addrs(name)

	case dns.TypeSRV:
		srv, target := c.dnsSRV(hdr(dns.TypeSRV), name)
		if srv == nil {
			return nil, nil
		}
		answer = append(answer, srv)
		extra = addrs(target)
	}

	return answer, extra
}

// dnsTXT builds the configured TXT answer.
func (c *ConfDNS) dnsTXT(hdr dns.RR_Header) dns.RR {
	return &dns.TXT{Hdr: hdr, Txt: []string{c.txtValue()}}
}

// dnsSOA builds a start-of-authority record naming this host as the primary
// nameserver for the queried name.
func (c *ConfDNS) dnsSOA(hdr dns.RR_Header, name string) dns.RR {
	zone := name
	if zone == "" {
		zone = "."
	}
	return &dns.SOA{
		Hdr:     hdr,
		Ns:      dnsJoin(c.serverHost(), zone),
		Mbox:    dnsJoin("hostmaster", zone),
		Serial:  1,
		Refresh: 900,
		Retry:   600,
		Expire:  86400,
		Minttl:  c.ttl(),
	}
}

// dnsSRV builds a service record pointing at the flamingo listener for the
// queried service, and returns the target name so glue addresses can be added.
// A service with no matching listener yields no record.
func (c *ConfDNS) dnsSRV(hdr dns.RR_Header, name string) (dns.RR, string) {
	service, zone, ok := dnsSRVService(name)
	if !ok {
		return nil, ""
	}
	port, ok := dnsSRVPorts[service]
	if !ok {
		return nil, ""
	}
	target := dnsJoin(c.serverHost(), zone)
	return &dns.SRV{
		Hdr:      hdr,
		Priority: 0,
		Weight:   100,
		Port:     port,
		Target:   target,
	}, target
}

// dnsJoin places a single label in front of a zone, handling the root zone,
// where there is nothing to join to.
func dnsJoin(label, zone string) string {
	if zone == "" || zone == "." {
		return dns.Fqdn(label)
	}
	return label + "." + dns.Fqdn(zone)
}

// dnsSRVService splits an SRV owner name into its service label and the zone
// the target should live in. RFC 2782 names are _service._proto.zone; Active
// Directory also uses _service._proto.<site>._sites.<zone> and
// _service._proto.dc._msdcs.<zone>, which split the same way because only the
// first label selects the service.
func dnsSRVService(name string) (service, zone string, ok bool) {
	labels := dns.SplitDomainName(strings.ToLower(name))
	if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") {
		return "", "", false
	}
	zone = dns.Fqdn(strings.Join(labels[2:], "."))
	if len(labels) == 2 {
		zone = "."
	}
	return labels[0], zone, true
}

// NewConfDNS creates a default configuration for the DNS capture server.
func NewConfDNS() *ConfDNS {
	return &ConfDNS{
		BindPort: 53,
		BindHost: "[::]",
		Network:  "udp",
	}
}

// SpawnDNS starts a new DNS capture server.
func SpawnDNS(c *ConfDNS) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	startServer := func(addr string) (*dns.Server, error) {
		wait := make(chan struct{})
		srv := &dns.Server{
			Net:               c.Network,
			Addr:              addr,
			NotifyStartedFunc: func() { close(wait) },
			Handler:           c,
		}
		fin := make(chan error, 1)
		go func() {
			fin <- srv.ListenAndServe()
		}()
		var errFromServer error
		select {
		case <-wait:
		case err := <-fin:
			errFromServer = err
		}
		return srv, errFromServer
	}

	server, err := startServer(addr)
	c.server = server
	log.Debugf("dns is listening on %s:%d", c.BindHost, c.BindPort)
	return err
}
