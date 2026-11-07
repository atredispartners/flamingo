package flamingo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	log "github.com/sirupsen/logrus"
)

// MSSQLServerName is the server name reported in TDS error messages.
var MSSQLServerName = "SQL01"

// TDS packet types.
const (
	mssqlPktTabular  = 0x04
	mssqlPktLogin7   = 0x10
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

// Message reassembly and session limits.
const (
	mssqlMaxMessage  = 32 * 1024
	mssqlMaxPackets  = 16
	mssqlMaxMessages = 3
	mssqlTimeout     = 30 * time.Second
)

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
func mssqlHandleConnection(c *ConfMSSQL, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mssqlTimeout))

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
			c.record(conn, login.fields())
			mssqlSendError(conn, 18456, fmt.Sprintf("Login failed for user '%s'.", login.Username))
			return
		default:
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
	if !l.SSPI {
		l.Password = str(44, true)
		if hdrLen == mssqlLoginHdrLen72 {
			l.ChangePassword = str(86, true)
		}
	}
	return l, nil
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

// mssqlWrite sends a single end-of-message TDS packet of the given type.
func mssqlWrite(conn net.Conn, typ byte, payload []byte) error {
	b := []byte{typ, 0x01, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(payload)+8))
	_, err := conn.Write(append(b, payload...))
	return err
}
