package flamingo

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
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

// ConfDNS describes the configuration of the dns service
type ConfDNS struct {
	BindPort uint16
	BindHost string
	// Network only supports UDP for now.
	Network      string
	ResolveToIP  string
	RecordWriter *RecordWriter
	shutdown     bool
	server       *dns.Server
	m            sync.Mutex
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

	if c.ResolveToIP == "" || len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeA {
		dns.HandleFailed(w, req)
		return
	}
	m := dns.Msg{}
	m.SetReply(req)
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP(c.ResolveToIP),
	}
	w.WriteMsg(&m)
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
	return err
}
