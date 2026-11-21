package flamingo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// MSSQLServerName is the server name reported in TDS error messages.
var MSSQLServerName = "SQL01"

// TDS packet types.
const (
	mssqlPktLogin    = 0x02 // TDS 4.2 and 5.0 login record
	mssqlPktTabular  = 0x04
	mssqlPktLogin7   = 0x10
	mssqlPktSSPI     = 0x11 // SSPI security token message
	mssqlPktPrelogin = 0x12
)

// PRELOGIN option tokens.
const (
	mssqlPreVersion    = 0x00
	mssqlPreEncryption = 0x01
	mssqlPreInstance   = 0x02
	mssqlPreThreadID   = 0x03
	mssqlPreMARS       = 0x04
	mssqlPreTerminator = 0xff
)

// mssqlEncryptNotSup is the PRELOGIN encryption value telling the client the
// server cannot negotiate TLS inside TDS. Clients that permit unencrypted
// logins then send LOGIN7 in the clear; clients that require encryption abort
// after the PRELOGIN exchange and yield no credential.
const mssqlEncryptNotSup = 0x02

// Message reassembly and session limits. A Windows Authentication login needs
// four messages: PRELOGIN, LOGIN7 carrying the NTLMSSP NEGOTIATE, and the SSPI
// message carrying the AUTHENTICATE, with one spare for a client that repeats
// its PRELOGIN.
const (
	mssqlMaxMessage  = 32 * 1024
	mssqlMaxPackets  = 16
	mssqlMaxMessages = 4
	mssqlTimeout     = 30 * time.Second
)

// mssqlMaxSSPI bounds the SSPI token taken from a LOGIN7 message. LOGIN7
// declares the token length in cbSSPI, or in cbSSPILong when it is 0xffff and
// the blob is larger than 64KB; either way the token has to fit inside a
// reassembled message, so anything longer is refused rather than trusted.
const mssqlMaxSSPI = mssqlMaxMessage

// LOGIN7 fixed header lengths. TDS 7.0 and 7.1 end after ibAtchDBFile; 7.2
// and later add ibChangePassword, cbChangePassword and cbSSPILong.
const (
	mssqlLoginHdrLen71 = 86
	mssqlLoginHdrLen72 = 94
)

// ConfMSSQL holds the configuration for a Microsoft SQL Server (TDS) capture server.
type ConfMSSQL struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfMSSQL creates a default configuration for the MSSQL capture server.
func NewConfMSSQL() *ConfMSSQL {
	return &ConfMSSQL{
		BindPort: 1433,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMSSQL) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMSSQL) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnMSSQL starts a logging MSSQL (TDS) server.
func SpawnMSSQL(c *ConfMSSQL) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("mssql is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go mssqlStart(c)
	return nil
}

func mssqlStart(c *ConfMSSQL) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go mssqlHandleConnection(c, conn)
	}
}

// record logs a captured LOGIN7 credential.
func (c *ConfMSSQL) record(conn net.Conn, fields map[string]string) {
	fields["_server"] = fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	c.RecordWriter.Record("credential", "mssql", conn.RemoteAddr().String(), fields)
}

// mssqlHandleConnection answers PRELOGIN without encryption, records the
// LOGIN7 credential and refuses the login with error 18456.
//
// A LOGIN7 carrying an NTLMSSP NEGOTIATE in its SSPI field is a Windows
// Authentication login: the CHALLENGE goes back in a TDS SSPI message, the
// client answers with another SSPI message carrying the AUTHENTICATE, and the
// NetNTLM response in it is what gets recorded.
func mssqlHandleConnection(c *ConfMSSQL, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mssqlTimeout))

	// The LOGIN7 whose SSPI exchange is in flight, and the client OS version
	// its NEGOTIATE advertised.
	var sspiLogin *mssqlLogin7
	var sspiVersion string

	for i := 0; i < mssqlMaxMessages; i++ {
		typ, msg, err := mssqlReadMessage(conn)
		if err != nil {
			return
		}
		switch typ {
		case mssqlPktPrelogin:
			// A TLS ClientHello wrapped in a PRELOGIN packet comes from a
			// client that ignored ENCRYPT_NOT_SUP; TLS in TDS is not supported.
			if len(msg) > 0 && msg[0] == 0x16 {
				return
			}
			if err := mssqlWrite(conn, mssqlPktTabular, mssqlPreloginResponse()); err != nil {
				return
			}
		case mssqlPktLogin7:
			login, err := mssqlParseLogin7(msg)
			if err != nil {
				log.Debugf("mssql login7 from %s: %s", conn.RemoteAddr(), err)
				return
			}
			if tok := FindNTLMSSP(login.SSPIToken); NTLMMessageType(tok) == NTLMTypeNegotiate {
				flags, version := ParseNTLMNegotiate(tok)
				if err := mssqlWrite(conn, mssqlPktSSPI, NTLMChallengeMessage(flags)); err != nil {
					return
				}
				sspiLogin, sspiVersion = login, version
				continue
			}
			c.record(conn, login.fields())
			mssqlSendError(conn, 18456, fmt.Sprintf("Login failed for user '%s'.", login.Username))
			return
		case mssqlPktSSPI:
			if sspiLogin == nil {
				log.Debugf("mssql SSPI message without a LOGIN7 from %s", conn.RemoteAddr())
				return
			}
			tok := FindNTLMSSP(msg)
			if NTLMMessageType(tok) != NTLMTypeAuthenticate {
				log.Debugf("mssql SSPI message type %d from %s, want AUTHENTICATE",
					NTLMMessageType(tok), conn.RemoteAddr())
				return
			}
			auth, err := ParseNTLMAuthenticate(tok)
			if err != nil {
				log.Debugf("mssql NTLM authenticate from %s: %s", conn.RemoteAddr(), err)
				return
			}
			c.record(conn, sspiLogin.ntlmFields(auth, sspiVersion))
			mssqlSendError(conn, 18456, fmt.Sprintf("Login failed for user '%s'.", mssqlNTLMUser(auth)))
			return
		case mssqlPktLogin:
			fields, err := mssqlParseLegacyLogin(msg)
			if err != nil {
				log.Debugf("mssql legacy login from %s: %s", conn.RemoteAddr(), err)
				return
			}
			c.record(conn, fields)
			mssqlSendLegacyError(conn, 18456, fmt.Sprintf("Login failed for user '%s'.", fields["username"]))
			return
		default:
			log.Debugf("mssql unexpected packet type 0x%02x from %s", typ, conn.RemoteAddr())
			return
		}
	}
}

// mssqlReadMessage reads TDS packets until the end-of-message status bit is
// set and returns the packet type with the reassembled payload.
func mssqlReadMessage(conn net.Conn) (byte, []byte, error) {
	var typ byte
	var msg []byte
	for i := 0; i < mssqlMaxPackets; i++ {
		var hdr [8]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return typ, nil, err
		}
		n := int(binary.BigEndian.Uint16(hdr[2:4]))
		if n < 8 || len(msg)+n-8 > mssqlMaxMessage {
			return hdr[0], nil, fmt.Errorf("bad packet length %d", n)
		}
		if i == 0 {
			typ = hdr[0]
		}
		body := make([]byte, n-8)
		if _, err := io.ReadFull(conn, body); err != nil {
			return typ, nil, err
		}
		msg = append(msg, body...)
		if hdr[1]&0x01 != 0 {
			return typ, msg, nil
		}
	}
	return typ, nil, errors.New("too many packets in message")
}

// mssqlPreloginResponse builds a SQL Server 2022 PRELOGIN reply that
// advertises ENCRYPT_NOT_SUP.
func mssqlPreloginResponse() []byte {
	opts := []struct {
		tok  byte
		data []byte
	}{
		{mssqlPreVersion, []byte{16, 0, 0x03, 0xe8, 0, 0}},
		{mssqlPreEncryption, []byte{mssqlEncryptNotSup}},
		{mssqlPreInstance, []byte{0}},
		{mssqlPreThreadID, nil},
		{mssqlPreMARS, []byte{0}},
	}
	off := len(opts)*5 + 1
	var hdr, data []byte
	for _, op := range opts {
		hdr = append(hdr, op.tok)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(off+len(data)))
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(op.data)))
		data = append(data, op.data...)
	}
	hdr = append(hdr, mssqlPreTerminator)
	return append(hdr, data...)
}

// mssqlLogin7 holds the fields decoded from a LOGIN7 message.
type mssqlLogin7 struct {
	TDSVersion     uint32
	ClientVersion  uint32
	ClientPID      uint32
	Hostname       string
	Username       string
	Password       string
	AppName        string
	ServerName     string
	Library        string
	Language       string
	Database       string
	ChangePassword string
	SSPI           bool
	SSPILength     int
	// SSPIToken is the security token carried in the LOGIN7 message, nil when
	// the login carries none or declares one that does not fit the message.
	SSPIToken []byte
}

// fields converts the decoded login into a credential record.
func (l *mssqlLogin7) fields() map[string]string {
	method := "sql"
	if l.SSPI {
		method = "sspi"
	}
	rec := map[string]string{
		"username":       l.Username,
		"password":       l.Password,
		"database":       l.Database,
		"hostname":       l.Hostname,
		"app_name":       l.AppName,
		"server_name":    l.ServerName,
		"library":        l.Library,
		"method":         method,
		"tds_version":    fmt.Sprintf("0x%08x", l.TDSVersion),
		"client_version": fmt.Sprintf("0x%08x", l.ClientVersion),
		"client_pid":     fmt.Sprintf("%d", l.ClientPID),
	}
	if l.Language != "" {
		rec["language"] = l.Language
	}
	if l.ChangePassword != "" {
		rec["change_password"] = l.ChangePassword
	}
	if l.SSPI {
		rec["sspi_length"] = fmt.Sprintf("%d", l.SSPILength)
	}
	return rec
}

// ntlmFields merges the identity and challenge responses captured from an
// NTLMSSP AUTHENTICATE message into the LOGIN7 record. negotiateVersion is the
// client OS version from the NEGOTIATE, used when the AUTHENTICATE carries
// none. The LOGIN7 client_version is the TDS client library version, so the
// NTLM VERSION field is recorded separately as client_os_version.
func (l *mssqlLogin7) ntlmFields(a *NTLMAuth, negotiateVersion string) map[string]string {
	rec := l.fields()
	rec["method"] = "NTLMSSP"
	rec["username"] = a.User
	rec["domain"] = a.Domain
	rec["workstation"] = a.Workstation
	rec["ntlm_version"] = a.NTLMVersion()
	if line, mode := NTLMHashcat(a); line != "" {
		rec["hashcat"] = line
		rec["hashcat_mode"] = strconv.Itoa(mode)
	}
	version := a.Version
	if version == "" {
		version = negotiateVersion
	}
	if version != "" {
		rec["client_os_version"] = version
	}
	return rec
}

// mssqlNTLMUser formats the authenticating identity for the login failure
// message the way SQL Server names a Windows account.
func mssqlNTLMUser(a *NTLMAuth) string {
	if a.Domain != "" {
		return a.Domain + "\\" + a.User
	}
	return a.User
}

// mssqlDecodeString extracts a UTF-16LE string referenced by an offset and
// character count pair in the LOGIN7 header. Password fields are stored
// obfuscated: each byte has its nibbles swapped and is XORed with 0xA5.
func mssqlDecodeString(p []byte, at, hdrLen int, password bool) string {
	le := binary.LittleEndian
	off, cch := int(le.Uint16(p[at:])), int(le.Uint16(p[at+2:]))
	if cch == 0 || off < hdrLen || off+2*cch > len(p) {
		return ""
	}
	b := append([]byte(nil), p[off:off+2*cch]...)
	if password {
		for i, v := range b {
			v ^= 0xa5
			b[i] = v<<4 | v>>4
		}
	}
	u := make([]uint16, cch)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// mssqlParseLogin7 decodes the fixed header and variable strings of a LOGIN7
// message. SSPI logins carry a security token instead of a password.
func mssqlParseLogin7(p []byte) (*mssqlLogin7, error) {
	if len(p) < mssqlLoginHdrLen71 {
		return nil, errors.New("short LOGIN7")
	}
	le := binary.LittleEndian
	// The high byte of the TDS version is the major: 0x70 through 0x74.
	hdrLen := mssqlLoginHdrLen71
	if p[7] >= 0x72 {
		hdrLen = mssqlLoginHdrLen72
	}
	if len(p) < hdrLen {
		return nil, errors.New("short LOGIN7")
	}
	str := func(at int, password bool) string {
		return mssqlDecodeString(p, at, hdrLen, password)
	}
	l := &mssqlLogin7{
		TDSVersion:    le.Uint32(p[4:]),
		ClientVersion: le.Uint32(p[12:]),
		ClientPID:     le.Uint32(p[16:]),
		Hostname:      str(36, false),
		Username:      str(40, false),
		AppName:       str(48, false),
		ServerName:    str(52, false),
		Library:       str(60, false),
		Language:      str(64, false),
		Database:      str(68, false),
		SSPILength:    int(le.Uint16(p[80:])),
	}
	if hdrLen == mssqlLoginHdrLen72 && l.SSPILength == 0xffff {
		l.SSPILength = int(le.Uint32(p[90:]))
	}
	// OptionFlags2 fIntSecurity requests integrated authentication.
	l.SSPI = p[25]&0x80 != 0 || l.SSPILength > 0
	l.SSPIToken = mssqlSSPIToken(p, hdrLen, l.SSPILength)
	if !l.SSPI {
		l.Password = str(44, true)
		if hdrLen == mssqlLoginHdrLen72 {
			l.ChangePassword = str(86, true)
		}
	}
	return l, nil
}

// mssqlSSPIToken returns the SSPI security token a LOGIN7 message points at.
// ibSSPI sits after the 6-byte ClientID at offset 72, so the offset pair starts
// at 78. A token that overlaps the fixed header, runs past the end of the
// message, or is larger than a reassembled message can hold is refused.
func mssqlSSPIToken(p []byte, hdrLen, length int) []byte {
	if length <= 0 || length > mssqlMaxSSPI || len(p) < 80 {
		return nil
	}
	off := int(binary.LittleEndian.Uint16(p[78:]))
	if off < hdrLen || off+length > len(p) {
		return nil
	}
	return p[off : off+length]
}

// mssqlSendError writes an ERROR token followed by DONE with the error flag set.
func mssqlSendError(conn net.Conn, number uint32, msg string) {
	le := binary.LittleEndian
	var tok []byte
	tok = le.AppendUint32(tok, number)
	tok = append(tok, 1, 14) // state, class
	m := utf16.Encode([]rune(msg))
	tok = le.AppendUint16(tok, uint16(len(m)))
	for _, r := range m {
		tok = le.AppendUint16(tok, r)
	}
	s := utf16.Encode([]rune(MSSQLServerName))
	tok = append(tok, byte(len(s)))
	for _, r := range s {
		tok = le.AppendUint16(tok, r)
	}
	tok = append(tok, 0)          // procedure name length
	tok = le.AppendUint32(tok, 1) // line number
	b := []byte{0xaa}
	b = le.AppendUint16(b, uint16(len(tok)))
	b = append(b, tok...)
	b = append(b, 0xfd)
	b = le.AppendUint16(b, 0x0002) // DONE_ERROR
	b = le.AppendUint16(b, 0)
	b = le.AppendUint64(b, 0)
	mssqlWrite(conn, mssqlPktTabular, b)
}

// Offsets in the TDS 4.2/5.0 login record. Each name field is padded to its size
// and followed by one length byte.
const (
	mssqlLLHost       = 0   // client host name, 30
	mssqlLLUser       = 31  // user name, 30
	mssqlLLPassword   = 62  // password, 30
	mssqlLLHostProc   = 93  // host process id, 30
	mssqlLLApp        = 140 // application name, 30
	mssqlLLServer     = 171 // server name, 30
	mssqlLLRemotePw   = 202 // remote passwords, 255
	mssqlLLTDSVersion = 458 // 4 bytes
	mssqlLLProgName   = 462 // client library, 10
	mssqlLLProgVer    = 473 // 4 bytes
	mssqlLLLanguage   = 480 // language, 30
	mssqlLLSecFlags   = 514 // bit 0: password encrypted (sent after the login)
	mssqlLLCharset    = 525 // character set, 30
	mssqlLLPktSize    = 557 // packet size as text, 6
	mssqlLLNameLen    = 30
)

// mssqlParseLegacyLogin decodes a TDS 4.2/5.0 login record into a credential
// record.
func mssqlParseLegacyLogin(p []byte) (map[string]string, error) {
	if len(p) <= mssqlLLPassword+mssqlLLNameLen {
		return nil, errors.New("short legacy login")
	}
	field := func(at, n int) []byte {
		if at+n >= len(p) {
			return nil
		}
		return p[at : at+min(int(p[at+n]), n)]
	}
	str := func(at, n int) string { return mssqlByteString(field(at, n)) }
	rec := map[string]string{
		"login_record": "tds4",
		"method":       "sql",
		"username":     str(mssqlLLUser, mssqlLLNameLen),
		"password":     str(mssqlLLPassword, mssqlLLNameLen),
		"hostname":     str(mssqlLLHost, mssqlLLNameLen),
		"app_name":     str(mssqlLLApp, mssqlLLNameLen),
		"server_name":  str(mssqlLLServer, mssqlLLNameLen),
		"library":      str(mssqlLLProgName, 10),
	}
	if rp := field(mssqlLLRemotePw, 255); len(rp) >= 2 {
		// Pairs of (server name, password), each length-prefixed; an empty name
		// is the default for every remote server.
		srvLen := int(rp[0])
		if 1+srvLen < len(rp) {
			pwLen := int(rp[1+srvLen])
			if end := 2 + srvLen + pwLen; end <= len(rp) {
				if rpw := mssqlByteString(rp[2+srvLen : end]); rpw != rec["password"] {
					rec["remote_password"] = rpw
				}
			}
		}
	}
	if len(p) >= mssqlLLTDSVersion+4 {
		rec["tds_version"] = fmt.Sprintf("%d.%d", p[mssqlLLTDSVersion], p[mssqlLLTDSVersion+1])
	}
	if len(p) >= mssqlLLProgVer+4 {
		rec["client_version"] = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(p[mssqlLLProgVer:]))
	}
	proc := str(mssqlLLHostProc, mssqlLLNameLen)
	if _, err := strconv.ParseUint(proc, 10, 32); err == nil {
		rec["client_pid"] = proc
	} else if proc != "" {
		rec["host_process"] = proc
	}
	if v := str(mssqlLLLanguage, mssqlLLNameLen); v != "" {
		rec["language"] = v
	}
	if v := str(mssqlLLCharset, mssqlLLNameLen); v != "" {
		rec["charset"] = v
	}
	if v := str(mssqlLLPktSize, 6); v != "" {
		rec["packet_size"] = v
	}
	if len(p) > mssqlLLSecFlags && p[mssqlLLSecFlags]&0x01 != 0 {
		rec["password_encrypted"] = "true"
	}
	return rec, nil
}

// mssqlByteString converts a single-byte login string: UTF-8 when it is valid,
// otherwise Latin-1, so every byte survives.
func mssqlByteString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, v := range b {
		r[i] = rune(v)
	}
	return string(r)
}

// mssqlSendLegacyError writes a TDS 4.2 ERROR token (single-byte strings,
// 2-byte line number) followed by DONE with the error flag and a 4-byte row
// count.
func mssqlSendLegacyError(conn net.Conn, number uint32, msg string) {
	le := binary.LittleEndian
	var tok []byte
	tok = le.AppendUint32(tok, number)
	tok = append(tok, 1, 14) // state, class
	tok = le.AppendUint16(tok, uint16(len(msg)))
	tok = append(tok, msg...)
	tok = append(tok, byte(len(MSSQLServerName)))
	tok = append(tok, MSSQLServerName...)
	tok = append(tok, 0)          // procedure name length
	tok = le.AppendUint16(tok, 1) // line number
	b := []byte{0xaa}
	b = le.AppendUint16(b, uint16(len(tok)))
	b = append(b, tok...)
	b = append(b, 0xfd)
	b = le.AppendUint16(b, 0x0002) // DONE_ERROR
	b = le.AppendUint16(b, 0)
	b = le.AppendUint32(b, 0)
	mssqlWrite(conn, mssqlPktTabular, b)
}

// mssqlWrite sends a single end-of-message TDS packet of the given type.
func mssqlWrite(conn net.Conn, typ byte, payload []byte) error {
	b := []byte{typ, 0x01, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(payload)+8))
	_, err := conn.Write(append(b, payload...))
	return err
}
