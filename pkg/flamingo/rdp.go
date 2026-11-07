package flamingo

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// rdpTimeout is the deadline applied to each client connection.
const rdpTimeout = 30 * time.Second

// X.224 TPDU codes and RDP negotiation structure types.
const (
	rdpTPKTVersion              = 3
	rdpX224CR                   = 0xe0
	rdpX224CC                   = 0xd0
	rdpX224DR                   = 0x80
	rdpX224DT                   = 0xf0
	rdpNegReq                   = 0x01
	rdpNegRsp                   = 0x02
	rdpNegRspExtendedClientData = 0x01
)

// Security protocols of RDP_NEG_REQ.
const (
	rdpProtocolRDP      uint32 = 0
	rdpProtocolSSL      uint32 = 1
	rdpProtocolHybrid   uint32 = 2
	rdpProtocolHybridEx uint32 = 8
)

// Limits on what the handler reads from a client.
const (
	rdpMaxTPKT = 32 << 10
	rdpMaxDER  = 16 << 10
	rdpMaxPDUs = 48
)

// MCS domain PDU choices (T.125) as the high six bits of the first byte.
const (
	rdpMCSErectDomainRequest  = 1
	rdpMCSDisconnectUltimatum = 8
	rdpMCSAttachUserRequest   = 10
	rdpMCSAttachUserConfirm   = 11
	rdpMCSChannelJoinRequest  = 14
	rdpMCSChannelJoinConfirm  = 15
	rdpMCSSendDataRequest     = 25
)

// MCS identifiers the server hands out.
const (
	rdpMCSBaseID      = 1001
	rdpMCSIOChannel   = 1003
	rdpMCSUserID      = 1007
	rdpMCSMaxChannels = 31
)

// GCC client and server data block types.
const (
	rdpCSCore     = 0xC001
	rdpCSSecurity = 0xC002
	rdpCSNet      = 0xC003
	rdpSCCore     = 0x0C01
	rdpSCSecurity = 0x0C02
	rdpSCNet      = 0x0C03
)

// Security header flag marking a Client Info PDU and the Client Info flag
// selecting Unicode strings.
const (
	rdpSecInfoPkt  = 0x0040
	rdpInfoUnicode = 0x10
)

// GCC Conference Create markers.
var (
	rdpT124Identifier = []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	rdpH221ClientKey  = []byte("Duca")
	rdpH221ServerKey  = []byte("McDn")
)

// ConfRDP describes the options for an RDP capture service. A certificate
// is required for TLS and NLA; without one only standard RDP security can
// be negotiated and no credential is produced.
type ConfRDP struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	tls          *tls.Config
	m            sync.Mutex
}

// NewConfRDP creates a default configuration for the RDP capture server.
func NewConfRDP() *ConfRDP {
	return &ConfRDP{
		BindPort: 3389,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfRDP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfRDP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnRDP starts a logging RDP server.
func SpawnRDP(c *ConfRDP) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	if c.TLSCert != "" {
		tlsConfig, err := c.tlsConfig()
		if err != nil {
			return fmt.Errorf("failed to load tls cert for rdp on %s (%s)", addr, err)
		}
		c.tls = tlsConfig
	} else {
		log.Debugf("rdp on %s has no tls certificate, only standard security will be negotiated and no credentials can be captured", addr)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("rdp is listening on %s", addr)
	go rdpStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfRDP) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

func rdpStart(c *ConfRDP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go rdpHandleConnection(c, conn)
	}
}

// rdpSession tracks the state of a single client connection.
type rdpSession struct {
	conf       *ConfRDP
	conn       net.Conn
	cookieUser string
	requested  uint32
}

// rdpConnReq is a parsed X.224 Connection Request.
type rdpConnReq struct {
	cookie    string
	hasNeg    bool
	protocols uint32
}

// rdpHandleConnection negotiates the security protocol and runs the matching
// capture flow until the credential is recorded or the client gives up.
func rdpHandleConnection(c *ConfRDP, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(rdpTimeout))

	s := &rdpSession{conf: c, conn: conn}
	if err := s.serve(); err != nil {
		log.Debugf("rdp %s: %s", conn.RemoteAddr(), err)
	}
}

// serve reads the X.224 Connection Request, selects the strongest protocol
// the client and the configuration both support, confirms it and dispatches
// to the matching flow.
func (s *rdpSession) serve() error {
	body, err := s.readTPKT()
	if err != nil {
		return fmt.Errorf("x224: %w", err)
	}
	cr, err := rdpParseConnReq(body)
	if err != nil {
		return fmt.Errorf("x224: %w", err)
	}
	s.cookieUser = cr.cookie

	selected := rdpProtocolRDP
	if cr.hasNeg && s.conf.tls != nil {
		s.requested = cr.protocols
		switch {
		case cr.protocols&(rdpProtocolHybrid|rdpProtocolHybridEx) != 0:
			selected = rdpProtocolHybrid
		case cr.protocols&rdpProtocolSSL != 0:
			selected = rdpProtocolSSL
		}
	}
	if err := s.write(rdpConnectionConfirm(selected, cr.hasNeg)); err != nil {
		return err
	}

	switch selected {
	case rdpProtocolHybrid:
		return s.credssp()
	case rdpProtocolSSL:
		return s.tlsCleartext()
	}
	return s.standard()
}

// rdpParseConnReq decodes an X.224 Connection Request with its routing
// cookie and RDP negotiation request.
func rdpParseConnReq(b []byte) (*rdpConnReq, error) {
	if len(b) < 7 {
		return nil, errors.New("short Connection Request")
	}
	if b[1] != rdpX224CR {
		return nil, fmt.Errorf("unexpected TPDU 0x%02x", b[1])
	}
	if n := int(b[0]) + 1; n >= 7 && n < len(b) {
		b = b[:n]
	}
	cr := &rdpConnReq{}
	rest := b[7:]
	if i := bytes.Index(rest, []byte("\r\n")); i >= 0 && len(rest) > 0 && rest[0] != rdpNegReq {
		line := strings.ToValidUTF8(string(rest[:i]), "?")
		rest = rest[i+2:]
		if v, ok := strings.CutPrefix(line, "Cookie: mstshash="); ok {
			cr.cookie = v
		}
	}
	if len(rest) >= 8 && rest[0] == rdpNegReq {
		cr.hasNeg = true
		cr.protocols = binary.LittleEndian.Uint32(rest[4:8])
	}
	return cr, nil
}

// rdpConnectionConfirm builds the X.224 Connection Confirm, with an
// RDP_NEG_RSP selecting protocol when the client sent an RDP_NEG_REQ.
func rdpConnectionConfirm(protocol uint32, neg bool) []byte {
	body := []byte{0, rdpX224CC, 0, 0, 0x12, 0x34, 0}
	if neg {
		body = append(body, rdpNegRsp, rdpNegRspExtendedClientData, 8, 0)
		body = binary.LittleEndian.AppendUint32(body, protocol)
	}
	body[0] = byte(len(body) - 1)
	return rdpTPKT(body)
}

// record logs a captured credential with the given method and fields, adding
// the routing cookie user when the client sent one.
func (s *rdpSession) record(method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", s.conf.BindHost, s.conf.BindPort),
		"method":  method,
	}
	if s.cookieUser != "" {
		rec["cookie_user"] = s.cookieUser
	}
	maps.Copy(rec, fields)
	s.conf.RecordWriter.Record("credential", "rdp", s.conn.RemoteAddr().String(), rec)
}

// credssp terminates TLS and runs the NTLM exchange inside CredSSP, refusing
// the credentials with STATUS_LOGON_FAILURE once the AUTHENTICATE message
// has been recorded.
func (s *rdpSession) credssp() error {
	if err := s.startTLS(); err != nil {
		return err
	}
	req, msg, err := s.readNTLM(1)
	if err != nil {
		return err
	}
	version := uint32(rdpCredSSPVersion)
	if req.version != 0 && req.version < version {
		version = req.version
	}
	flags, _ := rdpNTLMParseNegotiate(msg)
	if err := s.write(rdpEncodeTSRequest(version, rdpNTLMChallengeMessage(flags), nil)); err != nil {
		return err
	}
	_, msg, err = s.readNTLM(3)
	if err != nil {
		return err
	}
	a, err := rdpNTLMParseAuthenticate(msg)
	if err != nil {
		return fmt.Errorf("credssp: %w", err)
	}

	fields := map[string]string{
		"username":     a.user,
		"domain":       a.domain,
		"ntlm_version": a.ntlmVersion(),
		"challenge":    hex.EncodeToString(RDPNTLMChallenge[:]),
		"response":     hex.EncodeToString(a.nt),
	}
	if a.workstation != "" {
		fields["workstation"] = a.workstation
	}
	if a.version != "" {
		fields["client_version"] = a.version
	}
	if line := rdpNTLMHashcat(a); line != "" {
		fields["hashcat"] = line
	}
	s.record("credssp", fields)

	code := uint32(rdpStatusLogonFailure)
	return s.write(rdpEncodeTSRequest(version, nil, &code))
}

// readNTLM reads a TSRequest and returns it with the NTLMSSP message of the
// given type from its nego token.
func (s *rdpSession) readNTLM(want uint32) (*rdpTSRequest, []byte, error) {
	raw, err := rdpReadDER(s.conn)
	if err != nil {
		return nil, nil, fmt.Errorf("credssp: %w", err)
	}
	req, err := rdpParseTSRequest(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("credssp: %w", err)
	}
	if len(req.tokens) == 0 {
		return nil, nil, errors.New("credssp: TSRequest without nego token")
	}
	msg := rdpNTLMFind(req.tokens[0])
	if msg == nil {
		return nil, nil, errors.New("credssp: non-NTLM nego token")
	}
	if typ := rdpNTLMType(msg); typ != want {
		return nil, nil, fmt.Errorf("credssp: NTLM message type %d, want %d", typ, want)
	}
	return req, msg, nil
}

// tlsCleartext terminates TLS and walks the MCS connect sequence to the
// Client Info PDU, which carries the credentials in cleartext under TLS
// security.
func (s *rdpSession) tlsCleartext() error {
	if err := s.startTLS(); err != nil {
		return err
	}
	cd, err := s.connectInitial()
	if err != nil || cd == nil {
		return err
	}
	if err := s.write(rdpConnectResponse(s.requested, cd.channels)); err != nil {
		return err
	}
	for i := 0; i < rdpMaxPDUs; i++ {
		p, err := s.readMCS()
		if err != nil || p == nil {
			return err
		}
		switch p[0] >> 2 {
		case rdpMCSErectDomainRequest:
		case rdpMCSAttachUserRequest:
			if err := s.write(rdpAttachUserConfirm()); err != nil {
				return err
			}
		case rdpMCSChannelJoinRequest:
			if len(p) < 5 {
				return errors.New("mcs: short Channel Join Request")
			}
			initiator := binary.BigEndian.Uint16(p[1:3])
			channel := binary.BigEndian.Uint16(p[3:5])
			if err := s.write(rdpChannelJoinConfirm(initiator, channel)); err != nil {
				return err
			}
		case rdpMCSSendDataRequest:
			data, err := rdpSendDataRequest(p)
			if err != nil {
				return fmt.Errorf("mcs: %w", err)
			}
			if len(data) < 4 || binary.LittleEndian.Uint16(data[0:2])&rdpSecInfoPkt == 0 {
				continue
			}
			info, err := rdpParseClientInfo(data[4:])
			if err != nil {
				return fmt.Errorf("client_info: %w", err)
			}
			fields := map[string]string{
				"username": info.user,
				"domain":   info.domain,
				"password": info.password,
			}
			if cd.name != "" {
				fields["workstation"] = cd.name
			}
			s.record("client_info", fields)
			return s.write(rdpDisconnectUltimatum())
		case rdpMCSDisconnectUltimatum:
			return nil
		default:
			return fmt.Errorf("mcs: unexpected PDU %d", p[0]>>2)
		}
	}
	return errors.New("mcs: too many PDUs")
}

// standard reads the MCS Connect Initial of a client that negotiated
// standard RDP security, which needs RSA and RC4 and is not served further.
func (s *rdpSession) standard() error {
	cd, err := s.connectInitial()
	if err != nil || cd == nil {
		return err
	}
	log.Debugf("rdp %s negotiated standard security (client %q), no credential captured", s.conn.RemoteAddr(), cd.name)
	return nil
}

// connectInitial reads the MCS Connect Initial and returns its client data.
// A clean close instead of the PDU (probes stop after the Connection
// Confirm) returns nil data without an error.
func (s *rdpSession) connectInitial() (*rdpClientData, error) {
	p, err := s.readMCS()
	if err != nil || p == nil {
		return nil, err
	}
	cd, err := rdpParseConnectInitial(p)
	if err != nil {
		return nil, fmt.Errorf("mcs: %w", err)
	}
	return cd, nil
}

// readMCS reads the next non-empty MCS domain PDU. A client disconnect or
// a clean close returns nil without an error.
func (s *rdpSession) readMCS() ([]byte, error) {
	for {
		body, err := s.readTPKT()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, fmt.Errorf("mcs: %w", err)
		}
		if len(body) < 3 || body[0] != 2 {
			return nil, errors.New("x224: bad data TPDU")
		}
		switch body[1] {
		case rdpX224DT:
			if len(body) > 3 {
				return body[3:], nil
			}
		case rdpX224DR:
			return nil, nil
		default:
			return nil, fmt.Errorf("x224: unexpected TPDU 0x%02x", body[1])
		}
	}
}

// startTLS upgrades the connection in place using the configured
// certificate.
func (s *rdpSession) startTLS() error {
	tlsConn := tls.Server(s.conn, s.conf.tls)
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	tlsConn.SetDeadline(time.Now().Add(rdpTimeout))
	s.conn = tlsConn
	return nil
}

// readTPKT reads one TPKT and returns its payload.
func (s *rdpSession) readTPKT() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != rdpTPKTVersion {
		return nil, fmt.Errorf("TPKT version %d", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 7 || n > rdpMaxTPKT {
		return nil, fmt.Errorf("TPKT length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(s.conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// write sends b to the client.
func (s *rdpSession) write(b []byte) error {
	_, err := s.conn.Write(b)
	return err
}

// rdpTPKT frames b in a TPKT header.
func rdpTPKT(b []byte) []byte {
	h := []byte{rdpTPKTVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(h[2:], uint16(len(b)+4))
	return append(h, b...)
}

// rdpX224Data frames b as an X.224 Data TPDU in a TPKT.
func rdpX224Data(b []byte) []byte {
	return rdpTPKT(append([]byte{2, rdpX224DT, 0x80}, b...))
}

// rdpClientData is what the GCC Conference Create Request carries.
type rdpClientData struct {
	name     string
	channels int
}

// rdpClientInfo is the credential portion of a TS_INFO_PACKET.
type rdpClientInfo struct {
	domain, user, password string
}

// rdpPERLen decodes a PER length determinant.
func rdpPERLen(b []byte) (n, hdr int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), 1, true
	}
	if b[0]&0xc0 != 0x80 || len(b) < 2 {
		return 0, 0, false
	}
	return int(b[0]&0x3f)<<8 | int(b[1]), 2, true
}

// rdpPERLenBytes encodes a PER length determinant.
func rdpPERLenBytes(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(n>>8), byte(n)}
}

// rdpParseConnectInitial decodes an MCS Connect Initial and returns the
// client data of its GCC Conference Create Request.
func rdpParseConnectInitial(b []byte) (*rdpClientData, error) {
	if len(b) < 3 || b[0] != 0x7f || b[1] != 0x65 {
		return nil, errors.New("not an MCS Connect Initial")
	}
	n, hdr, ok := rdpBERLen(b[2:])
	if !ok {
		return nil, errors.New("bad Connect Initial length")
	}
	content := b[2+hdr:]
	if n < len(content) {
		content = content[:n]
	}
	var userData []byte
	for i := 0; i < 8 && len(content) > 0; i++ {
		tag, val, rest, ok := rdpDERNext(content)
		if !ok {
			break
		}
		content = rest
		if tag == 0x04 {
			userData = val
		}
	}
	if userData == nil {
		return nil, errors.New("Connect Initial without user data")
	}
	i := bytes.Index(userData, rdpH221ClientKey)
	if i < 0 {
		return nil, errors.New("no Conference Create Request")
	}
	blocks := userData[i+len(rdpH221ClientKey):]
	n, hdr, ok = rdpPERLen(blocks)
	if !ok {
		return nil, errors.New("bad client data length")
	}
	blocks = blocks[hdr:]
	if n < len(blocks) {
		blocks = blocks[:n]
	}
	return rdpParseClientBlocks(blocks), nil
}

// rdpParseClientBlocks walks the client data blocks for the client name in
// TS_UD_CS_CORE and the channel count in TS_UD_CS_NET.
func rdpParseClientBlocks(b []byte) *rdpClientData {
	cd := &rdpClientData{}
	for i := 0; i < 32 && len(b) >= 4; i++ {
		typ, n := binary.LittleEndian.Uint16(b[0:2]), int(binary.LittleEndian.Uint16(b[2:4]))
		if n < 4 || n > len(b) {
			break
		}
		d := b[4:n]
		b = b[n:]
		switch typ {
		case rdpCSCore:
			if len(d) >= 52 {
				cd.name = rdpUTF16String(d[20:52])
			}
		case rdpCSNet:
			if len(d) >= 4 {
				count := int(binary.LittleEndian.Uint32(d))
				if count > rdpMCSMaxChannels || 4+12*count > len(d) {
					count = min(rdpMCSMaxChannels, (len(d)-4)/12)
				}
				cd.channels = count
			}
		}
	}
	return cd
}

// rdpGCCBlock builds a GCC user data block.
func rdpGCCBlock(typ uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, typ)
	b = binary.LittleEndian.AppendUint16(b, uint16(4+len(data)))
	return append(b, data...)
}

// rdpConnectResponse builds an MCS Connect Response with a GCC Conference
// Create Response that selects TLS security and assigns ids to the
// requested channels.
func rdpConnectResponse(requested uint32, channels int) []byte {
	var core []byte
	core = binary.LittleEndian.AppendUint32(core, 0x00080004)
	core = binary.LittleEndian.AppendUint32(core, requested)
	core = binary.LittleEndian.AppendUint32(core, 0)
	var net []byte
	net = binary.LittleEndian.AppendUint16(net, rdpMCSIOChannel)
	net = binary.LittleEndian.AppendUint16(net, uint16(channels))
	for i := 0; i < channels; i++ {
		net = binary.LittleEndian.AppendUint16(net, uint16(rdpMCSIOChannel+1+i))
	}
	if channels%2 == 1 {
		net = append(net, 0, 0)
	}
	blocks := append(rdpGCCBlock(rdpSCCore, core), rdpGCCBlock(rdpSCNet, net)...)
	blocks = append(blocks, rdpGCCBlock(rdpSCSecurity, make([]byte, 8))...)

	// ConferenceCreateResponse: nodeID 1001, tag 1, result success, one user data set.
	inner := []byte{0x14, 0x76, 0x0a, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x00}
	inner = append(inner, rdpH221ServerKey...)
	inner = append(inner, rdpPERLenBytes(len(blocks))...)
	inner = append(inner, blocks...)
	gcc := append(append([]byte(nil), rdpT124Identifier...), rdpPERLenBytes(len(inner))...)
	gcc = append(gcc, inner...)

	params := []byte{0x02, 0x01, 0x22, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
		0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xf8, 0x02, 0x01, 0x02}
	content := []byte{0x0a, 0x01, 0x00, 0x02, 0x01, 0x00}
	content = append(content, rdpDERWrap(0x30, params)...)
	content = append(content, rdpDERWrap(0x04, gcc)...)
	out := append([]byte{0x7f, 0x66}, rdpBERLenBytes(len(content))...)
	return rdpX224Data(append(out, content...))
}

// rdpAttachUserConfirm builds an Attach User Confirm assigning rdpMCSUserID.
func rdpAttachUserConfirm() []byte {
	b := []byte{rdpMCSAttachUserConfirm<<2 | 0x02, 0x00}
	return rdpX224Data(binary.BigEndian.AppendUint16(b, rdpMCSUserID-rdpMCSBaseID))
}

// rdpChannelJoinConfirm builds a Channel Join Confirm for channel id ch.
func rdpChannelJoinConfirm(initiator, ch uint16) []byte {
	b := []byte{rdpMCSChannelJoinConfirm<<2 | 0x02, 0x00}
	b = binary.BigEndian.AppendUint16(b, initiator)
	b = binary.BigEndian.AppendUint16(b, ch)
	return rdpX224Data(binary.BigEndian.AppendUint16(b, ch))
}

// rdpDisconnectUltimatum builds a Disconnect Provider Ultimatum with reason
// rn-user-requested.
func rdpDisconnectUltimatum() []byte {
	return rdpX224Data([]byte{rdpMCSDisconnectUltimatum << 2, 0x80})
}

// rdpSendDataRequest returns the user data of a Send Data Request.
func rdpSendDataRequest(p []byte) ([]byte, error) {
	if len(p) < 7 {
		return nil, errors.New("short Send Data Request")
	}
	n, hdr, ok := rdpPERLen(p[6:])
	if !ok {
		return nil, errors.New("bad Send Data Request length")
	}
	data := p[6+hdr:]
	if n > len(data) {
		return nil, errors.New("truncated Send Data Request")
	}
	return data[:n], nil
}

// rdpParseClientInfo decodes the domain, user name and password of a
// TS_INFO_PACKET.
func rdpParseClientInfo(p []byte) (*rdpClientInfo, error) {
	if len(p) < 18 {
		return nil, errors.New("short Client Info")
	}
	flags := binary.LittleEndian.Uint32(p[4:8])
	unicode := flags&rdpInfoUnicode != 0
	nul := 1
	if unicode {
		nul = 2
	}
	off := 18
	str := func(at int) (string, error) {
		n := int(binary.LittleEndian.Uint16(p[at:]))
		if off+n+nul > len(p) {
			return "", errors.New("truncated Client Info field")
		}
		b := p[off : off+n]
		off += n + nul
		if unicode {
			return rdpUTF16String(b), nil
		}
		return strings.ToValidUTF8(strings.TrimRight(string(b), "\x00"), "?"), nil
	}
	var vals [3]string
	for i := range vals {
		v, err := str(8 + 2*i)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return &rdpClientInfo{domain: vals[0], user: vals[1], password: vals[2]}, nil
}
