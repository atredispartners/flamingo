package flamingo

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// poisonBindHosts maps a configured bind host to the IPv4 and IPv6 wildcard (or
// literal) hosts to listen on. An empty string disables that family.
func poisonBindHosts(bindHost string) (v4host, v6host string) {
	h := strings.Trim(bindHost, "[]")
	switch h {
	case "", "::", "0.0.0.0", "*":
		return "0.0.0.0", "::"
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return "0.0.0.0", "::"
	}
	if ip.To4() != nil {
		return h, ""
	}
	return "", h
}

// openPoisonV4 opens a UDP/IPv4 poisoner socket with SO_REUSEADDR set. When group
// is non-nil it joins that multicast group on every usable interface (failures
// logged and skipped, never fatal). It enables arrival-interface control messages.
func openPoisonV4(host string, port uint16, group net.IP, proto string) (*ipv4.PacketConn, error) {
	lc := net.ListenConfig{Control: poisonListenControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	v4 := ipv4.NewPacketConn(pc)
	if group != nil {
		if n := joinMulticastV4(v4, group, proto); n == 0 {
			log.Debugf("%s: no interfaces joined %s (continuing)", proto, group)
		}
		_ = v4.SetMulticastTTL(255)
	}
	// Not all platforms support this; the spoof-IP fallback covers failures.
	_ = v4.SetControlMessage(ipv4.FlagInterface, true)
	return v4, nil
}

// openPoisonV6 is the IPv6 counterpart of openPoisonV4.
func openPoisonV6(host string, port uint16, group net.IP, proto string) (*ipv6.PacketConn, error) {
	lc := net.ListenConfig{Control: poisonListenControl}
	pc, err := lc.ListenPacket(context.Background(), "udp6", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	v6 := ipv6.NewPacketConn(pc)
	if group != nil {
		if n := joinMulticastV6(v6, group, proto); n == 0 {
			log.Debugf("%s: no interfaces joined %s (continuing)", proto, group)
		}
		_ = v6.SetMulticastHopLimit(255)
	}
	_ = v6.SetControlMessage(ipv6.FlagInterface, true)
	return v6, nil
}

// poisonHandler processes one datagram and returns the reply bytes (nil to send
// nothing). It is responsible for recording the observed query.
type poisonHandler func(data []byte, src net.Addr, ifIndex int) []byte

// poisonServeV4 reads datagrams from an IPv4 poisoner socket until shutdown,
// dispatching each to handle and unicasting any reply back to the querier.
func poisonServeV4(c *ipv4.PacketConn, proto string, isShutdown func() bool, handle poisonHandler) {
	buf := make([]byte, 4096)
	for {
		if isShutdown() {
			return
		}
		n, cm, src, err := c.ReadFrom(buf)
		if err != nil {
			if isShutdown() {
				return
			}
			continue
		}
		ifIndex := 0
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		if resp := safePoisonHandle(proto, data, src, ifIndex, handle); resp != nil {
			if _, werr := c.WriteTo(resp, nil, src); werr != nil {
				log.Debugf("%s: failed to reply to %s: %s", proto, src, werr)
			}
		}
	}
}

// poisonServeV6 is the IPv6 counterpart of poisonServeV4.
func poisonServeV6(c *ipv6.PacketConn, proto string, isShutdown func() bool, handle poisonHandler) {
	buf := make([]byte, 4096)
	for {
		if isShutdown() {
			return
		}
		n, cm, src, err := c.ReadFrom(buf)
		if err != nil {
			if isShutdown() {
				return
			}
			continue
		}
		ifIndex := 0
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		if resp := safePoisonHandle(proto, data, src, ifIndex, handle); resp != nil {
			if _, werr := c.WriteTo(resp, nil, src); werr != nil {
				log.Debugf("%s: failed to reply to %s: %s", proto, src, werr)
			}
		}
	}
}

// safePoisonHandle runs a handler, recovering from a malformed-packet panic the
// way the other flamingo decoders do.
func safePoisonHandle(proto string, data []byte, src net.Addr, ifIndex int, handle poisonHandler) (resp []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("%s decoder panic with data %x: %q", proto, data, r)
			resp = nil
		}
	}()
	return handle(data, src, ifIndex)
}

// be32 appends a big-endian uint32 to b.
func be32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// Per-protocol default answer TTLs (seconds). These match the values Windows
// itself emits; they are also on Responder's own detection blacklist, so the
// --poison-ttl override exists to let an operator pick a less-fingerprintable
// value.
const (
	defaultLLMNRTTL uint32 = 30     // 0x0000001e
	defaultNBTNSTTL uint32 = 300000 // 0x000493e0
	defaultMDNSTTL  uint32 = 120    // 0x00000078
)

// ipMatcher matches a source address against a single IP, a CIDR network, or
// an inclusive range. It is the unit the IP allow/deny lists are built from.
type ipMatcher struct {
	single net.IP
	cidr   *net.IPNet
	lo, hi net.IP
}

// match reports whether ip falls inside this matcher.
func (m *ipMatcher) match(ip net.IP) bool {
	if ip == nil {
		return false
	}
	switch {
	case m.cidr != nil:
		return m.cidr.Contains(ip)
	case m.single != nil:
		return m.single.Equal(ip)
	case m.lo != nil && m.hi != nil:
		return ipInRange(ip, m.lo, m.hi)
	}
	return false
}

// ipInRange reports whether ip is within [lo, hi] inclusive. All three are
// normalized to their 16-byte form before comparison so v4 and v6 compare
// consistently.
func ipInRange(ip, lo, hi net.IP) bool {
	ip16, lo16, hi16 := ip.To16(), lo.To16(), hi.To16()
	if ip16 == nil || lo16 == nil || hi16 == nil {
		return false
	}
	return bytes.Compare(ip16, lo16) >= 0 && bytes.Compare(ip16, hi16) <= 0
}

// parseIPMatcher parses a single allow/deny list entry. Supported forms:
//   - a bare address:            10.0.0.5  or  fe80::1
//   - a CIDR network:            10.0.0.0/24
//   - a full range:              10.0.0.10-10.0.0.40
//   - a last-octet range:        10.0.0.10-40
func parseIPMatcher(entry string) (*ipMatcher, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, fmt.Errorf("empty ip entry")
	}

	if strings.Contains(entry, "/") {
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, err
		}
		return &ipMatcher{cidr: n}, nil
	}

	if i := strings.IndexByte(entry, '-'); i >= 0 {
		loStr := strings.TrimSpace(entry[:i])
		hiStr := strings.TrimSpace(entry[i+1:])
		lo := net.ParseIP(loStr)
		if lo == nil {
			return nil, fmt.Errorf("invalid range start %q", loStr)
		}
		var hi net.IP
		if strings.ContainsAny(hiStr, ".:") {
			hi = net.ParseIP(hiStr)
		} else if dot := strings.LastIndexByte(loStr, '.'); dot >= 0 {
			// Last-octet shorthand, e.g. 10.0.0.10-40.
			hi = net.ParseIP(loStr[:dot+1] + hiStr)
		}
		if hi == nil {
			return nil, fmt.Errorf("invalid range end %q", hiStr)
		}
		return &ipMatcher{lo: lo, hi: hi}, nil
	}

	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("invalid ip %q", entry)
	}
	return &ipMatcher{single: ip}, nil
}

// parseIPMatchers parses a comma-separated list of matcher entries.
func parseIPMatchers(spec string) ([]*ipMatcher, error) {
	var out []*ipMatcher
	for _, entry := range splitList(spec) {
		m, err := parseIPMatcher(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// splitList splits a comma-separated flag value into trimmed, non-empty parts.
func splitList(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ScopePolicy constrains which poisoner queries are answered so an operator can
// stay inside an authorized engagement scope. A zero-value policy answers every
// query. All name comparisons are case-insensitive.
type ScopePolicy struct {
	// RespondTo, when non-empty, is an allowlist of querier source addresses;
	// a querier whose address matches nothing here is never answered.
	RespondTo []*ipMatcher
	// DontRespondTo is a denylist of querier source addresses.
	DontRespondTo []*ipMatcher
	// RespondToName, when non-empty, is an allowlist of queried names.
	RespondToName []string
	// DontRespondToName is a denylist of queried names.
	DontRespondToName []string
	// DontRespondToTLD is a denylist of queried-name suffixes (e.g. _dosvc).
	DontRespondToTLD []string
	// Analyze turns the poisoner into a pure observer: queries are still
	// parsed, filtered, and logged, but no answer is ever sent.
	Analyze bool
}

// NewScopePolicy builds a ScopePolicy from comma-separated flag values.
func NewScopePolicy(respondTo, dontRespondTo, respondToName, dontRespondToName, dontRespondToTLD string, analyze bool) (*ScopePolicy, error) {
	p := &ScopePolicy{Analyze: analyze}

	var err error
	if p.RespondTo, err = parseIPMatchers(respondTo); err != nil {
		return nil, fmt.Errorf("respond-to: %w", err)
	}
	if p.DontRespondTo, err = parseIPMatchers(dontRespondTo); err != nil {
		return nil, fmt.Errorf("dont-respond-to: %w", err)
	}

	p.RespondToName = splitList(respondToName)
	p.DontRespondToName = splitList(dontRespondToName)
	p.DontRespondToTLD = splitList(dontRespondToTLD)
	return p, nil
}

// ShouldRespond reports whether the poisoner should answer a query from srcIP
// for name. When it should not, the returned reason explains why, for logging.
func (p *ScopePolicy) ShouldRespond(srcIP net.IP, name string) (bool, string) {
	if p == nil {
		return true, ""
	}
	if p.Analyze {
		return false, "analyze mode"
	}
	if !p.respondToIP(srcIP) {
		return false, "source address out of scope"
	}
	if !p.respondToName(name) {
		return false, "name out of scope"
	}
	return true, ""
}

func (p *ScopePolicy) respondToIP(ip net.IP) bool {
	for _, m := range p.DontRespondTo {
		if m.match(ip) {
			return false
		}
	}
	if len(p.RespondTo) > 0 {
		for _, m := range p.RespondTo {
			if m.match(ip) {
				return true
			}
		}
		return false
	}
	return true
}

func (p *ScopePolicy) respondToName(name string) bool {
	up := strings.ToUpper(strings.TrimSpace(name))
	for _, tld := range p.DontRespondToTLD {
		if strings.HasSuffix(up, strings.ToUpper(tld)) {
			return false
		}
	}
	for _, n := range p.DontRespondToName {
		if up == strings.ToUpper(n) {
			return false
		}
	}
	if len(p.RespondToName) > 0 {
		for _, n := range p.RespondToName {
			if up == strings.ToUpper(n) {
				return true
			}
		}
		return false
	}
	return true
}

// classifyDNSQuery inspects the trailing QTYPE/QCLASS of an LLMNR or mDNS query
// and returns a human-readable query type, whether an AAAA (IPv6) answer is
// wanted, and whether the query is one we answer at all. The classification is
// taken from the final four bytes of the datagram, matching the wire layout of
// a single-question LLMNR/mDNS query.
func classifyDNSQuery(data []byte) (qtype string, wantV6 bool, ok bool) {
	if len(data) < 4 {
		return "", false, false
	}
	switch {
	case bytes.Equal(data[len(data)-4:], []byte{0x00, 0x01, 0x00, 0x01}):
		return "A", false, true
	case bytes.Equal(data[len(data)-4:], []byte{0x00, 0xff, 0x00, 0x01}):
		return "ANY", false, true
	case bytes.Equal(data[len(data)-4:], []byte{0x00, 0x1c, 0x00, 0x01}):
		return "AAAA", true, true
	}
	return "", false, false
}

// parseLabelName reads a length-prefixed DNS label chain starting at offset and
// returns the dotted name. It stops at a zero length byte or the end of data.
func parseLabelName(data []byte, offset int) (string, bool) {
	var labels []string
	i := offset
	for i < len(data) {
		l := int(data[i])
		i++
		if l == 0 {
			break
		}
		if i+l > len(data) {
			return "", false
		}
		labels = append(labels, string(data[i:i+l]))
		i += l
	}
	if len(labels) == 0 {
		return "", false
	}
	return strings.Join(labels, "."), true
}

// usableMulticastIface reports whether an interface can carry multicast joins.
func usableMulticastIface(ifi net.Interface) bool {
	if ifi.Flags&net.FlagUp == 0 {
		return false
	}
	if ifi.Flags&net.FlagMulticast == 0 {
		return false
	}
	if ifi.Flags&net.FlagLoopback != 0 {
		return false
	}
	return true
}

// joinMulticastV4 attempts to join group on every usable interface. Per-interface
// failures are logged and skipped, never fatal. It returns the number of joins.
func joinMulticastV4(pc *ipv4.PacketConn, group net.IP, proto string) int {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debugf("%s: failed to enumerate interfaces: %s", proto, err)
		return 0
	}
	joined := 0
	for i := range ifaces {
		ifi := ifaces[i]
		if !usableMulticastIface(ifi) {
			continue
		}
		if err := pc.JoinGroup(&ifi, &net.UDPAddr{IP: group}); err != nil {
			log.Debugf("%s: failed to join %s on interface %s: %s", proto, group, ifi.Name, err)
			continue
		}
		log.Debugf("%s: joined %s on interface %s", proto, group, ifi.Name)
		joined++
	}
	return joined
}

// joinMulticastV6 is the IPv6 counterpart of joinMulticastV4.
func joinMulticastV6(pc *ipv6.PacketConn, group net.IP, proto string) int {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debugf("%s: failed to enumerate interfaces: %s", proto, err)
		return 0
	}
	joined := 0
	for i := range ifaces {
		ifi := ifaces[i]
		if !usableMulticastIface(ifi) {
			continue
		}
		if err := pc.JoinGroup(&ifi, &net.UDPAddr{IP: group}); err != nil {
			log.Debugf("%s: failed to join %s on interface %s: %s", proto, group, ifi.Name, err)
			continue
		}
		log.Debugf("%s: joined %s on interface %s", proto, group, ifi.Name)
		joined++
	}
	return joined
}

// ifaceIPv4 returns the first routable IPv4 address of the interface with the
// given index, or nil if none can be found.
func ifaceIPv4(ifIndex int) net.IP {
	if ifIndex <= 0 {
		return nil
	}
	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil
	}
	return firstIPv4(ifi)
}

// ifaceIPv6 returns the first usable IPv6 address of the interface with the
// given index, or nil if none can be found.
func ifaceIPv6(ifIndex int) net.IP {
	if ifIndex <= 0 {
		return nil
	}
	ifi, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return nil
	}
	return firstIPv6(ifi)
}

func firstIPv4(ifi *net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ip := addrIP(a)
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
			return ip4
		}
	}
	return nil
}

func firstIPv6(ifi *net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	// Prefer a global/ULA address; fall back to link-local, which is still
	// reachable on-link for a poisoned answer.
	var linkLocal net.IP
	for _, a := range addrs {
		ip := addrIP(a)
		if ip == nil || ip.To4() != nil {
			continue
		}
		if ip.IsLoopback() {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			if linkLocal == nil {
				linkLocal = ip
			}
			continue
		}
		return ip
	}
	return linkLocal
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// defaultIPv4 returns a routable IPv4 address from the first usable interface.
func defaultIPv4() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ip := firstIPv4(&ifi); ip != nil {
			return ip
		}
	}
	return nil
}

// defaultIPv6 returns a usable IPv6 address from the first usable interface.
func defaultIPv6() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ip := firstIPv6(&ifi); ip != nil {
			return ip
		}
	}
	return nil
}

// srcIP extracts the net.IP from a UDP source address.
func srcIP(addr net.Addr) net.IP {
	if u, ok := addr.(*net.UDPAddr); ok {
		return u.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
