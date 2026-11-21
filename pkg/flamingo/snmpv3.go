package flamingo

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// SNMPv3 message and USM constants (RFC 3412, RFC 3414).
const (
	snmpVersion3        = 3
	snmpSecurityUSM     = 3
	snmpFlagAuth        = 0x01
	snmpFlagPriv        = 0x02
	snmpFlagReportable  = 0x04
	snmpMaxAuthParamLen = 64
	snmpMaxUserLen      = 64
	snmpMaxEngineIDLen  = 64
	snmpReportMaxSize   = 65507
)

// SNMPEngineID is the authoritative engine ID this collector reports during
// SNMPv3 discovery. Clients echo it back in the authenticated request, so it
// also appears in every captured hash line. The RFC 3411 layout is a 4-byte
// enterprise number with the high bit set, a format octet, and up to 27 bytes
// of engine-chosen data; enterprise 8072 is net-snmp, which is what an
// unremarkable Linux agent would report.
var SNMPEngineID = []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x1c, 0x6d, 0x0f, 0x3a, 0x29, 0x5e, 0x11}

// snmpEngineBoots is the boot counter reported during discovery. It only has
// to be stable within a run; clients echo whatever we hand them.
var snmpEngineBoots int64 = 1

// snmpStartTime anchors the engine time reported during discovery.
var snmpStartTime = time.Now()

// snmpReportCounter supplies the varbind value in Report PDUs.
var snmpReportCounter atomic.Int64

// USM error OIDs returned in Report PDUs, pre-encoded. usmStatsUnknownEngineIDs
// tells a discovering client which engine ID to use; usmStatsWrongDigests tells
// an authenticating client the digest did not verify, which stops it retrying
// in a tight loop once its credential has been captured.
var (
	snmpOIDUnknownEngineIDs = []byte{0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00}
	snmpOIDWrongDigests     = []byte{0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x05, 0x00}
)

// SNMPv3 authentication types as they appear in the first field of a
// $SNMPv3$ hashcat line, and the hashcat mode that cracks each one. HMAC
// truncation lengths come from RFC 3414 (MD5, SHA1) and RFC 7860 (SHA-2), and
// are the only thing in the packet that identifies the algorithm: USM never
// names it on the wire. MD5-96 and SHA1-96 both truncate to 12 bytes and so
// cannot be told apart; hashcat mode 25000 tries both.
const (
	snmpAuthTypeMD5    = 0
	snmpAuthTypeSHA1   = 1
	snmpAuthTypeSHA224 = 2
	snmpAuthTypeSHA256 = 3
	snmpAuthTypeSHA384 = 4
	snmpAuthTypeSHA512 = 5
)

// snmpAuthAlgorithm describes the algorithm inferred from an authParameters
// length.
type snmpAuthAlgorithm struct {
	authType int
	name     string
	mode     int
}

// snmpAuthByParamLen maps the length of msgAuthenticationParameters to the
// algorithm that produced it.
var snmpAuthByParamLen = map[int]snmpAuthAlgorithm{
	12: {snmpAuthTypeMD5, "HMAC-MD5-96 or HMAC-SHA1-96", 25000},
	16: {snmpAuthTypeSHA224, "HMAC-SHA224-128", 26700},
	24: {snmpAuthTypeSHA256, "HMAC-SHA256-192", 26800},
	32: {snmpAuthTypeSHA384, "HMAC-SHA384-256", 26900},
	48: {snmpAuthTypeSHA512, "HMAC-SHA512-384", 27300},
}

// snmpV3Message is everything a captured SNMPv3 message yields.
type snmpV3Message struct {
	MsgID         int64
	Flags         byte
	SecurityModel int64

	EngineID    []byte
	EngineBoots int64
	EngineTime  int64
	Username    string
	AuthParams  []byte
	PrivParams  []byte

	// authParamsAt is the offset of the first authParameters content octet
	// within the original datagram. Zeroing that run in place is what turns
	// the captured packet into the input hashcat recomputes the HMAC over.
	authParamsAt int

	// RequestID is the PDU request-id when the scoped PDU is plaintext, and
	// zero when it is encrypted.
	RequestID int64
}

// Authenticated reports whether the message carries a USM digest.
func (m *snmpV3Message) Authenticated() bool {
	return m.Flags&snmpFlagAuth != 0 && len(m.AuthParams) > 0
}

// Encrypted reports whether the scoped PDU is privacy-protected.
func (m *snmpV3Message) Encrypted() bool {
	return m.Flags&snmpFlagPriv != 0
}

// snmpZeroedPacket returns a copy of the datagram with the authParameters
// content octets replaced by zeros, leaving every length and every other field
// byte-identical.
func (m *snmpV3Message) snmpZeroedPacket(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	if m.authParamsAt < 0 || m.authParamsAt+len(m.AuthParams) > len(out) {
		return out
	}
	for i := range m.AuthParams {
		out[m.authParamsAt+i] = 0
	}
	return out
}

// SNMPv3Hashcat formats a captured USM message as a hashcat $SNMPv3$ line and
// returns the mode that cracks it. The packet hex carries the authParameters
// zeroed in place, because that is the buffer the client ran the keyed HMAC
// over before dropping the digest into it. A message without a digest yields an
// empty line and a zero mode.
func SNMPv3Hashcat(m *snmpV3Message, data []byte) (string, int) {
	if m == nil || !m.Authenticated() {
		return "", 0
	}
	alg, ok := snmpAuthByParamLen[len(m.AuthParams)]
	if !ok {
		return "", 0
	}
	return fmt.Sprintf("$SNMPv3$%d$%d$%s$%s$%s",
		alg.authType,
		m.EngineBoots,
		hex.EncodeToString(m.snmpZeroedPacket(data)),
		hex.EncodeToString(m.EngineID),
		hex.EncodeToString(m.AuthParams),
	), alg.mode
}

// snmpParseV3 decodes an SNMPv3 message far enough to capture the USM
// credential material. Offsets are absolute within data so the authParameters
// run can be zeroed in the original packet.
func snmpParseV3(data []byte) (*snmpV3Message, error) {
	outer, err := berNext(data, 0)
	if err != nil {
		return nil, err
	}
	if outer.tag != berSequence {
		return nil, errors.New("not a sequence")
	}

	next := berChildren(data, outer)

	version, err := next()
	if err != nil {
		return nil, err
	}
	v, ok := berInt(version.content)
	if !ok || v != snmpVersion3 {
		return nil, errors.New("not version 3")
	}

	header, err := next()
	if err != nil {
		return nil, err
	}
	if header.tag != berSequence {
		return nil, errors.New("bad msgGlobalData")
	}

	m := &snmpV3Message{authParamsAt: -1}
	hdr := berChildren(data, header)
	if el, err := hdr(); err == nil {
		m.MsgID, _ = berInt(el.content)
	} else {
		return nil, err
	}
	if _, err := hdr(); err != nil { // msgMaxSize
		return nil, err
	}
	el, err := hdr()
	if err != nil {
		return nil, err
	}
	if len(el.content) > 0 {
		m.Flags = el.content[0]
	}
	if el, err := hdr(); err == nil {
		m.SecurityModel, _ = berInt(el.content)
	}

	secParams, err := next()
	if err != nil {
		return nil, err
	}
	if secParams.tag != berOctetString {
		return nil, errors.New("bad msgSecurityParameters")
	}
	if m.SecurityModel != snmpSecurityUSM {
		// Nothing to capture from a security model we cannot read, but the
		// header fields above are still worth reporting.
		return m, nil
	}
	if err := snmpParseUSM(data, secParams, m); err != nil {
		return nil, err
	}

	// The scoped PDU is only readable when privacy is off. A request-id is
	// nice to echo in a Report, and never essential.
	if scoped, err := next(); err == nil && !m.Encrypted() && scoped.tag == berSequence {
		m.RequestID = snmpScopedRequestID(data, scoped)
	}
	return m, nil
}

// snmpParseUSM decodes the USM security parameters, which are a BER SEQUENCE
// carried inside the msgSecurityParameters OCTET STRING.
func snmpParseUSM(data []byte, secParams berElement, m *snmpV3Message) error {
	usm, err := berNext(data, secParams.valueAt)
	if err != nil {
		return err
	}
	if usm.tag != berSequence || usm.end() > secParams.end() {
		return errors.New("bad USM parameters")
	}

	field := berChildren(data, usm)

	engineID, err := field()
	if err != nil {
		return err
	}
	if len(engineID.content) > snmpMaxEngineIDLen {
		return errors.New("engine id too long")
	}
	m.EngineID = engineID.content

	boots, err := field()
	if err != nil {
		return err
	}
	m.EngineBoots, _ = berInt(boots.content)

	etime, err := field()
	if err != nil {
		return err
	}
	m.EngineTime, _ = berInt(etime.content)

	user, err := field()
	if err != nil {
		return err
	}
	if len(user.content) > snmpMaxUserLen {
		return errors.New("username too long")
	}
	m.Username = string(user.content)

	auth, err := field()
	if err != nil {
		return err
	}
	if len(auth.content) > snmpMaxAuthParamLen {
		return errors.New("auth parameters too long")
	}
	m.AuthParams = auth.content
	m.authParamsAt = auth.valueAt

	if priv, err := field(); err == nil {
		m.PrivParams = priv.content
	}
	return nil
}

// snmpScopedRequestID digs the request-id out of a plaintext scoped PDU,
// returning zero when anything about it is unexpected.
func snmpScopedRequestID(data []byte, scoped berElement) int64 {
	field := berChildren(data, scoped)
	if _, err := field(); err != nil { // contextEngineID
		return 0
	}
	if _, err := field(); err != nil { // contextName
		return 0
	}
	pdu, err := field()
	if err != nil || pdu.tag&0xc0 != 0xa0 {
		return 0
	}
	reqID, err := berChildren(data, pdu)()
	if err != nil {
		return 0
	}
	v, _ := berInt(reqID.content)
	return v
}

// snmpProcessV3 records an SNMPv3 message and answers it with the Report PDU
// that keeps the client talking.
func snmpProcessV3(c *ConfSNMP, raddr net.Addr, data []byte) {
	m, err := snmpParseV3(data)
	if err != nil {
		log.Debugf("snmp: bad v3 message from %s: %s", raddr, err)
		return
	}

	fields := map[string]string{
		"_server":      fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"version":      "Version3",
		"username":     m.Username,
		"engine_id":    hex.EncodeToString(m.EngineID),
		"engine_boots": fmt.Sprintf("%d", m.EngineBoots),
		"engine_time":  fmt.Sprintf("%d", m.EngineTime),
		"encrypted":    fmt.Sprintf("%t", m.Encrypted()),
	}

	switch {
	case m.Authenticated():
		line, mode := SNMPv3Hashcat(m, data)
		if line == "" {
			// A digest of an unrecognised length: still a credential, just
			// not one that can be written as a hashcat line.
			fields["method"] = "usm"
			fields["auth_params"] = hex.EncodeToString(m.AuthParams)
			fields["auth_algorithm"] = fmt.Sprintf("unknown (%d-byte digest)", len(m.AuthParams))
			c.RecordWriter.Record("credential", "snmp", raddr.String(), fields)
			break
		}
		alg := snmpAuthByParamLen[len(m.AuthParams)]
		fields["method"] = "usm"
		fields["auth_algorithm"] = alg.name
		fields["hashcat"] = line
		fields["hashcat_mode"] = fmt.Sprintf("%d", mode)
		c.RecordWriter.Record("credential", "snmp", raddr.String(), fields)

	case m.Username != "":
		// A named user with no digest: noAuthNoPriv. There is no secret to
		// crack, but the user name itself is worth having.
		fields["method"] = "noauth"
		c.RecordWriter.Record("credential", "snmp", raddr.String(), fields)

	default:
		// Engine discovery: no user, no digest.
		fields["method"] = "discovery"
		c.RecordWriter.Record("access", "snmp", raddr.String(), fields)
	}

	if m.Flags&snmpFlagReportable == 0 {
		return
	}
	oid := snmpOIDUnknownEngineIDs
	if m.Authenticated() {
		oid = snmpOIDWrongDigests
	}
	resp := snmpBuildReport(m, oid)
	if resp == nil {
		return
	}
	if _, err := c.listener.WriteTo(resp, raddr); err != nil {
		log.Debugf("snmp: failed to answer %s: %s", raddr, err)
	}
}

// snmpBuildReport encodes an unauthenticated Report PDU naming this collector
// as the authoritative engine. A discovering client reads the engine ID, boots
// and time out of it and resends its request authenticated.
func snmpBuildReport(m *snmpV3Message, oid []byte) []byte {
	engineTime := int64(time.Since(snmpStartTime) / time.Second)

	usm := berTLV(berSequence, berCat(
		berTLV(berOctetString, SNMPEngineID),
		berTLV(berInteger, berIntBytes(snmpEngineBoots)),
		berTLV(berInteger, berIntBytes(engineTime)),
		berTLV(berOctetString, nil), // msgUserName
		berTLV(berOctetString, nil), // msgAuthenticationParameters
		berTLV(berOctetString, nil), // msgPrivacyParameters
	))

	varbind := berTLV(berSequence, berCat(
		berTLV(berOID, oid),
		berTLV(berCounter32, berIntBytes(snmpReportCounter.Add(1))),
	))

	pdu := berTLV(berReportPDU, berCat(
		berTLV(berInteger, berIntBytes(m.RequestID)),
		berTLV(berInteger, berIntBytes(0)), // error-status
		berTLV(berInteger, berIntBytes(0)), // error-index
		berTLV(berSequence, varbind),
	))

	scoped := berTLV(berSequence, berCat(
		berTLV(berOctetString, SNMPEngineID),
		berTLV(berOctetString, nil), // contextName
		pdu,
	))

	return berTLV(berSequence, berCat(
		berTLV(berInteger, berIntBytes(snmpVersion3)),
		berTLV(berSequence, berCat(
			berTLV(berInteger, berIntBytes(m.MsgID)),
			berTLV(berInteger, berIntBytes(snmpReportMaxSize)),
			berTLV(berOctetString, []byte{0x00}), // no auth, no priv, not reportable
			berTLV(berInteger, berIntBytes(snmpSecurityUSM)),
		)),
		berTLV(berOctetString, usm),
		scoped,
	))
}

// snmpMessageVersion peeks at the version field of an SNMP message without
// decoding the rest of it.
func snmpMessageVersion(data []byte) (int64, bool) {
	outer, err := berNext(data, 0)
	if err != nil || outer.tag != berSequence {
		return 0, false
	}
	version, err := berNext(data, outer.valueAt)
	if err != nil || version.tag != berInteger {
		return 0, false
	}
	return berInt(version.content)
}

// BER tags used by SNMP. SNMP never needs constructed-string or high-tag-number
// forms, so single-octet identifiers cover everything.
const (
	berInteger     byte = 0x02
	berOctetString byte = 0x04
	berOID         byte = 0x06
	berSequence    byte = 0x30
	berCounter32   byte = 0x41
	berReportPDU   byte = 0xa8
)

// berMaxDepthElements caps how many elements one sequence may yield, so a
// crafted packet cannot spin the parser.
const berMaxDepthElements = 64

// berElement is one decoded TLV, with offsets kept relative to the buffer it
// was decoded from so a field can be rewritten in the original packet.
type berElement struct {
	tag     byte
	start   int // offset of the identifier octet
	valueAt int // offset of the first content octet
	content []byte
}

// end returns the offset one past the last content octet.
func (e berElement) end() int { return e.valueAt + len(e.content) }

// berNext decodes the TLV starting at off. Only definite lengths and
// single-octet identifiers are accepted; everything else is an error rather
// than a guess.
func berNext(b []byte, off int) (berElement, error) {
	var e berElement
	if off < 0 || off >= len(b) {
		return e, errors.New("ber: out of range")
	}
	e.start = off
	e.tag = b[off]
	if e.tag&0x1f == 0x1f {
		return e, errors.New("ber: high tag numbers not supported")
	}
	off++
	if off >= len(b) {
		return e, errors.New("ber: truncated length")
	}

	length := int(b[off])
	off++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 {
			return e, errors.New("ber: indefinite length not supported")
		}
		if n > 4 || off+n > len(b) {
			return e, errors.New("ber: bad long-form length")
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[off+i])
		}
		off += n
	}
	if length < 0 || off+length > len(b) {
		return e, errors.New("ber: length past end of buffer")
	}

	e.valueAt = off
	e.content = b[off : off+length]
	return e, nil
}

// berChildren returns an iterator over the elements inside a constructed
// element. Each call yields the next child, or an error once the parent's
// content is exhausted.
func berChildren(b []byte, parent berElement) func() (berElement, error) {
	off := parent.valueAt
	end := parent.end()
	left := berMaxDepthElements
	return func() (berElement, error) {
		if left <= 0 {
			return berElement{}, errors.New("ber: too many elements")
		}
		left--
		if off >= end {
			return berElement{}, errors.New("ber: no more elements")
		}
		e, err := berNext(b, off)
		if err != nil {
			return e, err
		}
		if e.end() > end {
			return e, errors.New("ber: element overruns parent")
		}
		off = e.end()
		return e, nil
	}
}

// berInt decodes a two's-complement INTEGER of up to 8 octets.
func berInt(content []byte) (int64, bool) {
	if len(content) == 0 || len(content) > 8 {
		return 0, false
	}
	v := int64(0)
	if content[0]&0x80 != 0 {
		v = -1
	}
	for _, b := range content {
		v = v<<8 | int64(b)
	}
	return v, true
}

// berIntBytes encodes v as the shortest two's-complement INTEGER content.
func berIntBytes(v int64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	i := 0
	for i < 7 {
		// Drop a leading octet only when the next one carries the sign.
		if buf[i] == 0x00 && buf[i+1]&0x80 == 0 {
			i++
			continue
		}
		if buf[i] == 0xff && buf[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return buf[i:]
}

// berLenBytes encodes a definite length in the shortest permitted form.
func berLenBytes(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(n))
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := append([]byte{byte(0x80 | (8 - i))}, buf[i:]...)
	return out
}

// berTLV encodes one tag-length-value element.
func berTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+6)
	out = append(out, tag)
	out = append(out, berLenBytes(len(content))...)
	return append(out, content...)
}

// berCat concatenates encoded elements.
func berCat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
