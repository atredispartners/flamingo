package flamingo

import (
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

var dnsTypeMap = map[uint16]string{
	0:     "TypeNone",
	1:     "TypeA",
	2:     "TypeNS",
	3:     "TypeMD",
	4:     "TypeMF",
	5:     "TypeCNAME",
	6:     "TypeSOA",
	7:     "TypeMB",
	8:     "TypeMG",
	9:     "TypeMR",
	10:    "TypeNULL",
	12:    "TypePTR",
	13:    "TypeHINFO",
	14:    "TypeMINFO",
	15:    "TypeMX",
	16:    "TypeTXT",
	17:    "TypeRP",
	18:    "TypeAFSDB",
	19:    "TypeX25",
	20:    "TypeISDN",
	21:    "TypeRT",
	23:    "TypeNSAPPTR",
	24:    "TypeSIG",
	25:    "TypeKEY",
	26:    "TypePX",
	27:    "TypeGPOS",
	28:    "TypeAAAA",
	29:    "TypeLOC",
	30:    "TypeNXT",
	31:    "TypeEID",
	32:    "TypeNIMLOC",
	33:    "TypeSRV",
	34:    "TypeATMA",
	35:    "TypeNAPTR",
	36:    "TypeKX",
	37:    "TypeCERT",
	39:    "TypeDNAME",
	41:    "TypeOPT",
	42:    "TypeAPL",
	43:    "TypeDS",
	44:    "TypeSSHFP",
	46:    "TypeRRSIG",
	47:    "TypeNSEC",
	48:    "TypeDNSKEY",
	49:    "TypeDHCID",
	50:    "TypeNSEC3",
	51:    "TypeNSEC3PARAM",
	52:    "TypeTLSA",
	53:    "TypeSMIMEA",
	55:    "TypeHIP",
	56:    "TypeNINFO",
	57:    "TypeRKEY",
	58:    "TypeTALINK",
	59:    "TypeCDS",
	60:    "TypeCDNSKEY",
	61:    "TypeOPENPGPKEY",
	62:    "TypeCSYNC",
	99:    "TypeSPF",
	100:   "TypeUINFO",
	101:   "TypeUID",
	102:   "TypeGID",
	103:   "TypeUNSPEC",
	104:   "TypeNID",
	105:   "TypeL32",
	106:   "TypeL64",
	107:   "TypeLP",
	108:   "TypeEUI48",
	109:   "TypeEUI64",
	256:   "TypeURI",
	257:   "TypeCAA",
	258:   "TypeAVC",
	249:   "TypeTKEY",
	250:   "TypeTSIG",
	251:   "TypeIXFR",
	252:   "TypeAXFR",
	253:   "TypeMAILB",
	254:   "TypeMAILA",
	255:   "TypeANY",
	32768: "TypeTA",
	32769: "TypeDLV",
	65535: "TypeReserved",
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

// NewConfDNS creates a default configuration for the DNS capture server.
func NewConfDNS() *ConfDNS {
	return &ConfDNS{
		BindPort: 53,
		BindHost: "[::]",
		Network:  "udp",
	}
}

func newDNSHandler(c *ConfDNS) func(w dns.ResponseWriter, req *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		remoteAddr := w.RemoteAddr()
		for _, q := range req.Question {
			c.RecordWriter.Record(
				"dns",
				remoteAddr.String(),
				map[string]string{
					"name": q.Name,
					"type": dnsTypeMap[q.Qtype],
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
	dns.HandleFunc(".", newDNSHandler(c))
	server, err := startServer(addr)
	c.server = server
	return err
}
