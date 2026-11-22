package flamingo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	log "github.com/sirupsen/logrus"
)

// SMB1 commands this listener answers.
const (
	smb1CommandNegotiate        = 0x72
	smb1CommandSessionSetupAndX = 0x73
)

// SMB1 header flags.
const (
	smb1FlagsCaseInsensitive = 0x08
	smb1FlagsReply           = 0x80
)

// SMB1 header flags2.
const (
	smb1Flags2LongNames        = 0x0001
	smb1Flags2ExtendedSecurity = 0x0800
	smb1Flags2NTStatus         = 0x4000
	smb1Flags2Unicode          = 0x8000
)

// SMB1 NEGOTIATE response capabilities.
const (
	smb1CapUnicode    = 0x00000004
	smb1CapLargeFiles = 0x00000008
	smb1CapNTSMBs     = 0x00000010
	smb1CapRPCRemote  = 0x00000020
	smb1CapStatus32   = 0x00000040
	smb1CapNTFind     = 0x00000200
)

// smb1AndXNone terminates an AndX chain.
const smb1AndXNone = 0xff

// smb1NTLMDialect is the only SMB1 dialect this listener selects: it is the
// one that carries NT LM challenge/response credentials.
const smb1NTLMDialect = "NT LM 0.12"

// smb1NoDialect is the DialectIndex meaning "none of the offered dialects".
const smb1NoDialect = 0xffff

// smb1WildcardDialect is the SMB2 wildcard revision. Answering an SMB1
// multi-protocol NEGOTIATE with it tells the client to start again in SMB2.
const smb1WildcardDialect = 0x02ff

// smb1SMB2Dialects are the SMB1 dialect strings that mean "I also speak SMB2".
var smb1SMB2Dialects = []string{"SMB 2.002", "SMB 2.???"}

// smb1Magic opens every SMB1 header.
var smb1Magic = []byte{0xff, 'S', 'M', 'B'}

// smb1IsHeader reports whether pkt starts with an SMB1 header.
func smb1IsHeader(pkt []byte) bool {
	return len(pkt) >= 32 && bytes.Equal(pkt[:4], smb1Magic)
}

// handleSMB1 dispatches one SMB1 message and reports whether the connection
// should stay open.
func (s *smbSession) handleSMB1(pkt []byte) bool {
	switch pkt[4] {
	case smb1CommandNegotiate:
		return s.smb1Negotiate(pkt)
	case smb1CommandSessionSetupAndX:
		return s.smb1SessionSetup(pkt)
	}
	log.Debugf("smb1 command 0x%02x from %s, closing", pkt[4], s.conn.RemoteAddr())
	return false
}

// smb1Negotiate answers an SMB1 multi-protocol NEGOTIATE. A client that also
// offered SMB2 is pushed straight to SMB2 with the wildcard dialect; an
// SMB1-only client is answered with NT LM 0.12 and flamingo's fixed challenge
// so its SESSION_SETUP_ANDX carries an LM/NT response.
func (s *smbSession) smb1Negotiate(pkt []byte) bool {
	offered, err := smb1ParseNegotiate(pkt)
	if err != nil {
		log.Debugf("smb1 NEGOTIATE from %s: %s", s.conn.RemoteAddr(), err)
		return false
	}

	if smb1OffersSMB2(offered) {
		s.dialect = smbDialectName(smb1WildcardDialect)
		return s.write(smbNegotiateResponse(s.conf.serverGUID, 0, smb1WildcardDialect))
	}

	index := smb1DialectIndex(offered, smb1NTLMDialect)
	if index < 0 {
		// Only pre-NT dialects were offered; nothing here can carry a
		// challenge/response credential.
		log.Debugf("smb1 no NT dialect offered by %s", s.conn.RemoteAddr())
		s.write(s.smb1Response(pkt, smbStatusSuccess,
			binary.LittleEndian.AppendUint16(nil, smb1NoDialect), nil))
		return false
	}
	s.dialect = smb1NTLMDialect
	return s.write(s.smb1NegotiateResponse(pkt, index))
}

// smb1NegotiateResponse builds the NT LM 0.12 NEGOTIATE response.
//
// CAP_EXTENDED_SECURITY is deliberately not advertised. Without it the
// response carries flamingo's fixed challenge directly, which is what lets a
// genuinely old client — the only reason this code path exists — answer with
// an LM or NTLMv1 response in SESSION_SETUP_ANDX. Clients that do speak
// extended security are still handled if they use it anyway.
func (s *smbSession) smb1NegotiateResponse(req []byte, index int) []byte {
	unicode := smb1IsUnicode(req)

	caps := uint32(smb1CapLargeFiles | smb1CapNTSMBs | smb1CapRPCRemote | smb1CapStatus32 | smb1CapNTFind)
	if unicode {
		caps |= smb1CapUnicode
	}

	w := make([]byte, 34)
	le := binary.LittleEndian
	le.PutUint16(w[0:2], uint16(index))
	w[2] = 0x03 // user-level security, challenge/response passwords
	le.PutUint16(w[3:5], 50)
	le.PutUint16(w[5:7], 1)
	le.PutUint32(w[7:11], smbMaxBuffer)
	le.PutUint32(w[11:15], smbMaxBuffer)
	le.PutUint32(w[15:19], 0)
	le.PutUint32(w[19:23], caps)
	le.PutUint64(w[23:31], winFiletime(time.Now()))
	le.PutUint16(w[31:33], 0)
	w[33] = uint8(len(NTLMConf.Challenge))

	data := append([]byte(nil), NTLMConf.Challenge[:]...)
	// The byte block starts at an odd packet offset, so a UTF-16 name needs
	// one pad byte to land on a two-byte boundary.
	if unicode {
		data = append(data, 0)
	}
	data = append(data, smb1String(NTLMConf.NetBIOSDomainName, unicode)...)
	data = append(data, smb1String(NTLMConf.NetBIOSComputerName, unicode)...)
	return s.smb1Response(req, smbStatusSuccess, w, data)
}

// smb1SessionSetup records the credential carried by a SESSION_SETUP_ANDX, in
// either the extended-security (NTLMSSP) or the legacy LM/NT form.
func (s *smbSession) smb1SessionSetup(pkt []byte) bool {
	ss, err := smb1ParseSessionSetup(pkt)
	if err != nil {
		log.Debugf("smb1 SESSION_SETUP_ANDX from %s: %s", s.conn.RemoteAddr(), err)
		return false
	}
	if s.dialect == "" {
		s.dialect = smb1NTLMDialect
	}

	if len(ss.Blob) > 0 {
		return s.smb1ExtendedSecurity(pkt, ss)
	}

	if len(ss.NT) == 0 && len(ss.LM) == 0 {
		// An anonymous or guest setup carries no credential material.
		log.Debugf("smb1 SESSION_SETUP_ANDX without a response from %s", s.conn.RemoteAddr())
		s.write(s.smb1Response(pkt, smbStatusLogonFailure, nil, nil))
		return false
	}

	s.clientVersion = ss.NativeOS
	s.recordAuth(ss.auth(s.callingName))
	// Capture only: the credential is recorded, the logon is refused.
	s.write(s.smb1Response(pkt, smbStatusLogonFailure, nil, nil))
	return false
}

// smb1ExtendedSecurity runs the NTLMSSP exchange carried in a SESSION_SETUP_ANDX
// security blob.
func (s *smbSession) smb1ExtendedSecurity(pkt []byte, ss *smb1SessionSetup) bool {
	msg := FindNTLMSSP(ss.Blob)
	if msg == nil {
		log.Debugf("smb1 security blob without NTLMSSP from %s", s.conn.RemoteAddr())
		s.write(s.smb1Response(pkt, smbStatusLogonFailure, nil, nil))
		return false
	}

	switch NTLMMessageType(msg) {
	case NTLMTypeNegotiate:
		s.clientFlags, s.clientVersion = ParseNTLMNegotiate(msg)
		challenge, ok := s.challengeFor(msg)
		if !ok {
			return false
		}
		s.challenge = challenge
		blob := smbSPNEGONegTokenResp(challenge)
		w := make([]byte, 8)
		w[0] = smb1AndXNone
		binary.LittleEndian.PutUint16(w[6:8], uint16(len(blob)))
		data := append(append([]byte(nil), blob...), smb1String("", ss.Unicode)...)
		data = append(data, smb1String("", ss.Unicode)...)
		return s.write(s.smb1Response(pkt, smbStatusMoreProcessingRequired, w, data))

	case NTLMTypeAuthenticate:
		auth, err := ParseNTLMAuthenticate(msg)
		if err != nil {
			log.Debugf("smb1 AUTHENTICATE from %s: %s", s.conn.RemoteAddr(), err)
			return false
		}
		s.recordAuth(auth)
		status := uint32(smbStatusLogonFailure)
		if s.authenticated(auth, msg) {
			status = smbStatusSuccess
		}
		s.write(s.smb1Response(pkt, status, nil, nil))
		return false
	}

	log.Debugf("smb1 unexpected NTLMSSP message type %d from %s", NTLMMessageType(msg), s.conn.RemoteAddr())
	return false
}

// smb1Response builds an SMB1 reply header for req, followed by the given
// parameter words and data block.
func (s *smbSession) smb1Response(req []byte, status uint32, words, data []byte) []byte {
	pkt := make([]byte, 32)
	copy(pkt, smb1Magic)
	pkt[4] = req[4]
	binary.LittleEndian.PutUint32(pkt[5:9], status)
	pkt[9] = smb1FlagsReply | smb1FlagsCaseInsensitive
	flags2 := binary.LittleEndian.Uint16(req[10:12]) &
		(smb1Flags2Unicode | smb1Flags2ExtendedSecurity | smb1Flags2LongNames)
	binary.LittleEndian.PutUint16(pkt[10:12], flags2|smb1Flags2NTStatus)
	copy(pkt[24:32], req[24:32]) // TID, PID, UID and MID are echoed
	binary.LittleEndian.PutUint16(pkt[28:30], s.smb1UID)

	pkt = append(pkt, byte(len(words)/2))
	pkt = append(pkt, words...)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)))
	return append(pkt, data...)
}

// smb1IsUnicode reports whether an SMB1 message negotiated UTF-16 strings.
func smb1IsUnicode(pkt []byte) bool {
	return binary.LittleEndian.Uint16(pkt[10:12])&smb1Flags2Unicode != 0
}

// smb1String encodes a null-terminated SMB1 string.
func smb1String(s string, unicode bool) []byte {
	if !unicode {
		return append([]byte(s), 0)
	}
	return append(utf16Bytes(s), 0, 0)
}

// smb1ParseNegotiate returns the dialect strings offered in an SMB1
// NEGOTIATE request.
func smb1ParseNegotiate(pkt []byte) ([]string, error) {
	if len(pkt) < 35 {
		return nil, errors.New("short SMB1 NEGOTIATE")
	}
	if pkt[32] != 0 {
		return nil, fmt.Errorf("SMB1 NEGOTIATE with %d parameter words", pkt[32])
	}
	body := pkt[35:]
	if n := int(binary.LittleEndian.Uint16(pkt[33:35])); n < len(body) {
		body = body[:n]
	}
	var out []string
	for len(body) > 1 {
		if body[0] != 0x02 { // dialect buffer format
			break
		}
		body = body[1:]
		i := bytes.IndexByte(body, 0)
		if i < 0 {
			out = append(out, string(body))
			break
		}
		out = append(out, string(body[:i]))
		body = body[i+1:]
	}
	if len(out) == 0 {
		return nil, errors.New("SMB1 NEGOTIATE without dialects")
	}
	return out, nil
}

// smb1OffersSMB2 reports whether the dialect list includes an SMB2 entry.
func smb1OffersSMB2(offered []string) bool {
	for _, d := range offered {
		for _, smb2 := range smb1SMB2Dialects {
			if d == smb2 {
				return true
			}
		}
	}
	return false
}

// smb1DialectIndex returns the index of want in the offered dialects, or -1.
func smb1DialectIndex(offered []string, want string) int {
	for i, d := range offered {
		if d == want {
			return i
		}
	}
	return -1
}

// smb1SessionSetup holds the credential material of a SESSION_SETUP_ANDX
// request in whichever form the client used.
type smb1SessionSetup struct {
	// WordCount distinguishes the forms: 12 is extended security, 13 is the
	// NT LM 0.12 LM/NT response pair, and 10 is the pre-NT single password.
	WordCount int

	// Blob is the extended-security token, set only for word count 12.
	Blob []byte

	// LM and NT are the challenge responses of the legacy forms.
	LM []byte
	NT []byte

	Account      string
	Domain       string
	NativeOS     string
	NativeLM     string
	Capabilities uint32
	Unicode      bool
}

// auth converts a legacy SESSION_SETUP_ANDX into the shape the NTLM core
// formats. SMB1 carries no workstation name of its own, so the NetBIOS
// calling name stands in when one was seen.
func (ss *smb1SessionSetup) auth(callingName string) *NTLMAuth {
	flags := NTLMFlagNTLM
	if ss.Unicode {
		flags |= NTLMFlagUnicode
	}
	return &NTLMAuth{
		User:        ss.Account,
		Domain:      ss.Domain,
		Workstation: callingName,
		LM:          ss.LM,
		NT:          ss.NT,
		Flags:       flags,
	}
}

// smb1ParseSessionSetup decodes a SESSION_SETUP_ANDX request. Every field is
// bounds checked against the message: truncated or malformed input returns an
// error rather than panicking.
func smb1ParseSessionSetup(pkt []byte) (*smb1SessionSetup, error) {
	if len(pkt) < 33 {
		return nil, errors.New("short SMB1 SESSION_SETUP_ANDX")
	}
	wc := int(pkt[32])
	bcOff := 33 + wc*2
	if bcOff+2 > len(pkt) {
		return nil, errors.New("SMB1 SESSION_SETUP_ANDX truncated before ByteCount")
	}
	start := bcOff + 2
	data := pkt[start:]
	if n := int(binary.LittleEndian.Uint16(pkt[bcOff:])); n < len(data) {
		data = data[:n]
	}

	ss := &smb1SessionSetup{WordCount: wc, Unicode: smb1IsUnicode(pkt)}
	c := &smb1Cursor{data: data, base: start, unicode: ss.Unicode}
	le := binary.LittleEndian

	switch wc {
	case 12: // extended security
		ss.Capabilities = le.Uint32(pkt[53:57])
		ss.Blob = c.take(int(le.Uint16(pkt[47:49])))
	case 13: // NT LM 0.12 LM and NT responses
		ss.Capabilities = le.Uint32(pkt[55:59])
		ss.LM = c.take(int(le.Uint16(pkt[47:49])))
		ss.NT = c.take(int(le.Uint16(pkt[49:51])))
	case 10: // pre-NT single password
		// With user-level, challenge/response security this is an LM
		// response; a shorter value is a cleartext password, which the
		// NTLM formatter will simply decline to turn into a hash.
		ss.LM = c.take(int(le.Uint16(pkt[47:49])))
	default:
		return nil, fmt.Errorf("SMB1 SESSION_SETUP_ANDX with %d parameter words", wc)
	}

	c.align()
	if wc != 12 {
		ss.Account = c.str()
		ss.Domain = c.str()
	}
	ss.NativeOS = c.str()
	ss.NativeLM = c.str()
	return ss, nil
}

// smb1Cursor walks the byte block of an SMB1 message. base is the offset of
// data[0] within the packet, which is what UTF-16 alignment is measured from.
type smb1Cursor struct {
	data    []byte
	base    int
	pos     int
	unicode bool
}

// take returns the next n bytes, or everything that is left when the message
// is short.
func (c *smb1Cursor) take(n int) []byte {
	if n < 0 || n > len(c.data)-c.pos {
		n = len(c.data) - c.pos
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b
}

// align skips the pad byte that precedes a UTF-16 string when the cursor sits
// on an odd packet offset.
func (c *smb1Cursor) align() {
	if c.unicode && (c.base+c.pos)%2 != 0 && c.pos < len(c.data) {
		c.pos++
	}
}

// str reads one null-terminated string, UTF-16LE or single byte according to
// the negotiated flags.
func (c *smb1Cursor) str() string {
	rest := c.data[c.pos:]
	if !c.unicode {
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			c.pos = len(c.data)
			return smb1ByteString(rest)
		}
		c.pos += i + 1
		return smb1ByteString(rest[:i])
	}
	var u []uint16
	for i := 0; i+1 < len(rest); i += 2 {
		v := binary.LittleEndian.Uint16(rest[i:])
		if v == 0 {
			c.pos += i + 2
			return string(utf16.Decode(u))
		}
		u = append(u, v)
	}
	c.pos = len(c.data)
	return string(utf16.Decode(u))
}

// smb1ByteString trims a single-byte SMB1 string, keeping every byte by
// falling back to Latin-1 when it is not valid UTF-8.
func smb1ByteString(b []byte) string {
	return strings.ToValidUTF8(string(b), "?")
}
