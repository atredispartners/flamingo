package flamingo

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// mDNS multicast groups (RFC 6762).
var (
	mdnsGroupV4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupV6 = net.ParseIP("ff02::fb")
)

// ConfMDNS describes the options for the mDNS poisoner.
type ConfMDNS struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	Policy *ScopePolicy
	// AnswerBroadcast enables answering multicast and broadcast queries, the
	// active half of poisoning. Queries directed at this host are always
	// answered.
	AnswerBroadcast bool
	SpoofIPv4       string
	SpoofIPv6       string
	TTL             uint32

	shutdown bool
	v4       *ipv4.PacketConn
	v6       *ipv6.PacketConn
	m        sync.Mutex
}

// NewConfMDNS creates a default configuration for the mDNS poisoner.
func NewConfMDNS() *ConfMDNS {
	return &ConfMDNS{
		BindPort: 5353,
		BindHost: "[::]",
		TTL:      defaultMDNSTTL,
		Policy:   DefaultScopePolicy(),
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMDNS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMDNS) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.v4 != nil {
		c.v4.Close()
	}
	if c.v6 != nil {
		c.v6.Close()
	}
}

// SpawnMDNS starts an mDNS poisoner listening on the configured port.
//
// Name poisoning is active, not passive: answering is what makes hosts connect
// to flamingo. The line is drawn by reach, not by listener. This one runs by
// default -- it logs every query it sees and answers those sent directly to
// this host, like any other listener. Answering a query multicast to the
// segment reaches hosts that were never talking to flamingo, so that half
// needs AnswerBroadcast (--poison-broadcast), and the ScopePolicy and analyze
// mode narrow that half further, inside an authorized engagement scope. None
// of them gate the directed case: replying to a query aimed at this host is
// not poisoning.
func SpawnMDNS(c *ConfMDNS) error {
	v4host, v6host := poisonBindHosts(c.BindHost)

	var started bool
	if v4host != "" {
		v4, err := openPoisonV4(v4host, c.BindPort, mdnsGroupV4, "mdns")
		if err != nil {
			log.Debugf("mdns: failed to open IPv4 socket on %s:%d: %s", v4host, c.BindPort, err)
		} else {
			c.v4 = v4
			started = true
			go poisonServeV4(v4, "mdns", c.IsShutdown, c.handle)
		}
	}

	if v6host != "" {
		v6, err := openPoisonV6(v6host, c.BindPort, mdnsGroupV6, "mdns")
		if err != nil {
			log.Debugf("mdns: failed to open IPv6 socket on %s:%d: %s", v6host, c.BindPort, err)
		} else {
			c.v6 = v6
			started = true
			go poisonServeV6(v6, "mdns", c.IsShutdown, c.handle)
		}
	}

	if !started {
		return fmt.Errorf("failed to listen on %s:%d for mdns", c.BindHost, c.BindPort)
	}

	log.Debugf("mdns is listening on %s:%d", c.BindHost, c.BindPort)
	return nil
}

// parseMDNSQuery parses an mDNS query. It returns the dotted display name, the
// raw encoded QNAME bytes (to be echoed as the answer name), the query type,
// whether an AAAA answer is wanted, and whether the datagram is answerable.
func parseMDNSQuery(data []byte) (name string, rawName []byte, qtype string, wantV6, ok bool) {
	// Header (12) + at least a one-byte label + null + type (2) + class (2).
	if len(data) < 18 {
		return "", nil, "", false, false
	}
	// Parse the first question properly rather than slicing from the end of
	// the datagram. A query may carry several questions, and a client doing
	// known-answer suppression (RFC 6762 section 7.1) appends answer records
	// after them; a blind tail slice swallowed all of that into the name and
	// echoed it back as the answer's owner, producing a malformed reply.
	display, qEnd, nameOK := parseLabelNameEnd(data, 12)
	if !nameOK {
		return "", nil, "", false, false
	}
	// The answer name is the raw encoded labels without the terminating null.
	if qEnd-1 <= 12 {
		return "", nil, "", false, false
	}
	rawName = data[12 : qEnd-1]
	qtype, wantV6, ok = classifyDNSQueryAt(data, qEnd)
	if !ok {
		return "", nil, "", false, false
	}
	return display, rawName, qtype, wantV6, true
}

// buildMDNSAnswer builds a byte-exact mDNS response.
func buildMDNSAnswer(rawName []byte, wantV6 bool, ip net.IP, ttl uint32) []byte {
	rtype := []byte{0x00, 0x01} // A
	if wantV6 {
		rtype = []byte{0x00, 0x1c} // AAAA
	}

	out := make([]byte, 0, 64)
	out = append(out, 0x00, 0x00) // transaction id (mDNS uses 0)
	out = append(out, 0x84, 0x00) // flags: QR=1, AA=1
	out = append(out, 0x00, 0x00) // questions
	out = append(out, 0x00, 0x01) // answer RRs
	out = append(out, 0x00, 0x00) // authority RRs
	out = append(out, 0x00, 0x00) // additional RRs

	// Answer.
	out = append(out, rawName...)
	out = append(out, 0x00)
	out = append(out, rtype...)
	out = append(out, 0x00, 0x01) // class IN (cache-flush bit deliberately off)
	out = be32(out, ttl)

	if wantV6 {
		out = append(out, 0x00, 0x10)
		out = append(out, ip.To16()...)
	} else {
		out = append(out, 0x00, 0x04)
		out = append(out, ip.To4()...)
	}
	return out
}

// handle processes one mDNS datagram, records it, and returns any reply bytes.
func (c *ConfMDNS) handle(data []byte, src net.Addr, ifIndex int, dst net.IP) []byte {
	name, rawName, qtype, wantV6, ok := parseMDNSQuery(data)
	if !ok {
		return nil
	}

	respond, reason := poisonDecide(c.Policy, c.AnswerBroadcast, src, name, dst)

	var spoof net.IP
	if respond {
		spoof = c.chooseSpoof(wantV6, ifIndex, src)
		if spoof == nil {
			respond = false
			reason = "host has no routable address to answer with"
		}
	}

	c.record(src, name, qtype, respond, spoof, reason)
	if !respond {
		return nil
	}
	return buildMDNSAnswer(rawName, wantV6, spoof, c.TTL)
}

// chooseSpoof returns the address to answer with. A poisoner advertises its
// own address so the querier connects to flamingo's collectors; see
// poisonSpoofIP for the resolution order.
func (c *ConfMDNS) chooseSpoof(wantV6 bool, ifIndex int, src net.Addr) net.IP {
	override := c.SpoofIPv4
	if wantV6 {
		override = c.SpoofIPv6
	}
	return poisonSpoofIP(override, wantV6, ifIndex, src)
}

func (c *ConfMDNS) record(src net.Addr, name, qtype string, answered bool, spoof net.IP, reason string) {
	fields := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"name":     name,
		"qtype":    qtype,
		"answered": fmt.Sprintf("%t", answered),
	}
	if answered && spoof != nil {
		fields["spoofed"] = spoof.String()
	}
	if !answered && reason != "" {
		fields["reason"] = reason
	}
	c.RecordWriter.Record("query", "mdns", src.String(), fields)
}
