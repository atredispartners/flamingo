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
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// MySQLSalt is the fixed 20-byte auth plugin data (the "salt") sent in every
// HandshakeV10. A static salt, like the fixed VNC and NTLM challenges, lets
// captured mysql_native_password scrambles be cracked offline with
// precomputed material; the recorded hashcat line uses mode 11200. The bytes
// are arbitrary printable characters, as a real server would send, and the
// handshake layout requires exactly 20 of them.
var MySQLSalt = []byte("Fx7#pQ2!vLm9@kR4zW8&")

// mysqlServerVersion is the version string advertised in the handshake.
const mysqlServerVersion = "8.0.36"

// MySQL capability flags.
const (
	mysqlClientConnectWithDB    = 0x00000008
	mysqlClientProtocol41       = 0x00000200
	mysqlClientSSL              = 0x00000800
	mysqlClientSecureConnection = 0x00008000
	mysqlClientPluginAuth       = 0x00080000
	mysqlClientConnectAttrs     = 0x00100000
	mysqlClientPluginAuthLenenc = 0x00200000

	// mysqlServerCaps is what a MySQL 8.0 server offers, minus compression.
	mysqlServerCaps = 0x09FFFFDF
)

// Authentication plugin names.
const (
	mysqlPluginNative = "mysql_native_password"
	mysqlPluginSHA2   = "caching_sha2_password"
	mysqlPluginClear  = "mysql_clear_password"
	mysqlPluginOld    = "mysql_old_password"
)

const (
	// mysqlMaxPacket caps the size of a packet accepted from a client.
	mysqlMaxPacket = 16 * 1024
	// mysqlMaxAttrs caps the number of connection attributes parsed.
	mysqlMaxAttrs = 64
	// mysqlTimeout is the idle deadline applied to each client connection.
	mysqlTimeout = 30 * time.Second
)

// mysqlConnID supplies the connection id placed in each handshake.
var mysqlConnID atomic.Uint32

// ConfMySQL describes the options for a MySQL capture service. When a TLS
// certificate is configured the handshake advertises CLIENT_SSL and the
// connection is upgraded in place on an SSLRequest packet.
type ConfMySQL struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfMySQL creates a default configuration for the MySQL capture server.
func NewConfMySQL() *ConfMySQL {
	return &ConfMySQL{
		BindPort: 3306,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMySQL) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMySQL) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnMySQL starts a logging MySQL server.
func SpawnMySQL(c *ConfMySQL) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	if c.TLSCert != "" {
		if _, err := c.tlsConfig(); err != nil {
			return fmt.Errorf("failed to load tls cert for mysql on %s (%s)", addr, err)
		}
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("mysql is listening on %s", addr)
	go mysqlStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfMySQL) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

func mysqlStart(c *ConfMySQL) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go mysqlHandleConnection(c, conn)
	}
}

// record logs a captured credential with the given method and fields.
func (c *ConfMySQL) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", "mysql", conn.RemoteAddr().String(), rec)
}

// handshake builds the HandshakeV10 packet offering mysql_native_password.
func (c *ConfMySQL) handshake() []byte {
	caps := uint32(mysqlServerCaps)
	if c.TLSCert == "" {
		caps &^= mysqlClientSSL
	}
	b := []byte{10}
	b = append(b, mysqlServerVersion...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 8+mysqlConnID.Add(1))
	b = append(b, MySQLSalt[:8]...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps&0xffff))
	b = append(b, 255)                         // utf8mb4_0900_ai_ci
	b = binary.LittleEndian.AppendUint16(b, 2) // SERVER_STATUS_AUTOCOMMIT
	b = binary.LittleEndian.AppendUint16(b, uint16(caps>>16))
	b = append(b, byte(len(MySQLSalt)+1))
	b = append(b, make([]byte, 10)...)
	b = append(b, MySQLSalt[8:]...)
	b = append(b, 0)
	b = append(b, mysqlPluginNative...)
	return append(b, 0)
}

// mysqlSession tracks the state of a single client connection.
type mysqlSession struct {
	conf *ConfMySQL
	conn net.Conn
	seq  byte
}

// readPacket reads one MySQL packet and tracks the sequence number.
func (s *mysqlSession) readPacket() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	s.seq = hdr[3] + 1
	if n > mysqlMaxPacket {
		return nil, fmt.Errorf("packet length %d exceeds limit", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(s.conn, p); err != nil {
		return nil, err
	}
	return p, nil
}

// writePacket frames a payload with the next sequence number and sends it.
func (s *mysqlSession) writePacket(p []byte) error {
	b := make([]byte, 0, 4+len(p))
	b = append(b, byte(len(p)), byte(len(p)>>8), byte(len(p)>>16), s.seq)
	s.seq++
	_, err := s.conn.Write(append(b, p...))
	return err
}

// sendError writes an ERR packet with the given code, SQLSTATE and message.
func (s *mysqlSession) sendError(code uint16, state, msg string) {
	b := []byte{0xff}
	b = binary.LittleEndian.AppendUint16(b, code)
	b = append(b, '#')
	b = append(b, state...)
	b = append(b, msg...)
	s.writePacket(b)
}

// startTLS upgrades the connection in place after an SSLRequest packet.
func (s *mysqlSession) startTLS() error {
	tlsConfig, err := s.conf.tlsConfig()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	tlsConn.SetDeadline(time.Now().Add(mysqlTimeout))
	s.conn = tlsConn
	return nil
}

// mysqlHandleConnection sends the handshake, records the client's
// authentication response, tries to switch the client to the cleartext
// plugin, and rejects the login with the normal 1045 error.
func mysqlHandleConnection(c *ConfMySQL, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mysqlTimeout))
	s := &mysqlSession{conf: c, conn: conn}

	if err := s.writePacket(c.handshake()); err != nil {
		return
	}
	pkt, err := s.readPacket()
	if err != nil {
		return
	}

	// An SSLRequest is a 32-byte HandshakeResponse41 prefix with CLIENT_SSL set
	if len(pkt) == 32 && binary.LittleEndian.Uint32(pkt)&mysqlClientSSL != 0 {
		if c.TLSCert == "" {
			return
		}
		if err := s.startTLS(); err != nil {
			log.Debugf("mysql tls upgrade failed from %s: %s", conn.RemoteAddr(), err)
			return
		}
		if pkt, err = s.readPacket(); err != nil {
			return
		}
	}

	r, perr := mysqlParseResponse(pkt)
	if r.user == "" && perr != nil {
		return
	}
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	usingPassword := len(r.auth) > 0

	fields := map[string]string{
		"username":    r.user,
		"database":    r.database,
		"auth_plugin": r.plugin,
	}
	for attr, key := range map[string]string{
		"_client_name":    "client_name",
		"_client_version": "client_version",
		"program_name":    "program_name",
	} {
		if v := r.attrs[attr]; v != "" {
			fields[key] = v
		}
	}

	switch {
	case r.plugin == mysqlPluginClear:
		// The client already sent the password in the clear
		fields["password"] = string(bytes.TrimRight(r.auth, "\x00"))
		c.record(s.conn, mysqlPluginClear, fields)

	case len(r.auth) > 0:
		saltHex := hex.EncodeToString(MySQLSalt)
		respHex := hex.EncodeToString(r.auth)
		fields["salt"] = saltHex
		fields["response"] = respHex
		if r.plugin == mysqlPluginNative && len(r.auth) == 20 {
			fields["hashcat"] = fmt.Sprintf("$mysqlna$%s*%s", saltHex, respHex)
		}
		c.record(s.conn, r.plugin, fields)
	}

	// Ask clients that support plugin auth for the cleartext password
	if perr == nil && r.caps&mysqlClientPluginAuth != 0 && r.plugin != mysqlPluginClear {
		sw := append([]byte{0xfe}, mysqlPluginClear...)
		sw = append(sw, 0)
		if err := s.writePacket(sw); err != nil {
			return
		}
		if pw, err := s.readPacket(); err == nil {
			usingPassword = true
			clear := maps.Clone(fields)
			delete(clear, "salt")
			delete(clear, "response")
			delete(clear, "hashcat")
			clear["auth_plugin"] = mysqlPluginClear
			clear["password"] = string(bytes.TrimRight(pw, "\x00"))
			c.record(s.conn, mysqlPluginClear, clear)
		}
	}

	using := "NO"
	if usingPassword {
		using = "YES"
	}
	s.sendError(1045, "28000", fmt.Sprintf("Access denied for user '%s'@'%s' (using password: %s)", r.user, host, using))
}

// mysqlResponse holds the fields decoded from a HandshakeResponse41.
type mysqlResponse struct {
	caps     uint32
	user     string
	auth     []byte
	database string
	plugin   string
	attrs    map[string]string
}

var errMySQLShort = errors.New("truncated handshake response")

// mysqlParseResponse decodes a HandshakeResponse41, returning whatever it
// read before any error. Pre-4.1 responses yield the user and scramble with
// a non-nil error.
func mysqlParseResponse(p []byte) (mysqlResponse, error) {
	var r mysqlResponse
	if len(p) < 4 {
		return r, errMySQLShort
	}
	r.caps = binary.LittleEndian.Uint32(p)
	if r.caps&mysqlClientProtocol41 == 0 {
		// HandshakeResponse320: caps(2) max packet(3) user NUL auth
		if len(p) < 5 {
			return r, errMySQLShort
		}
		u, rest, _ := bytes.Cut(p[5:], []byte{0})
		r.user = string(u)
		r.auth = bytes.TrimRight(rest, "\x00")
		r.plugin = mysqlPluginOld
		return r, errors.New("pre-4.1 client")
	}
	if len(p) < 32 {
		return r, errMySQLShort
	}
	p = p[32:]
	u, rest, ok := bytes.Cut(p, []byte{0})
	r.user = string(u)
	if !ok {
		return r, errMySQLShort
	}
	p = rest
	switch {
	case r.caps&mysqlClientPluginAuthLenenc != 0:
		n, rest, ok := mysqlLenenc(p)
		if !ok || n > uint64(len(rest)) {
			return r, errMySQLShort
		}
		r.auth, p = rest[:n], rest[n:]
	case r.caps&mysqlClientSecureConnection != 0:
		if len(p) < 1 || int(p[0]) > len(p)-1 {
			return r, errMySQLShort
		}
		r.auth, p = p[1:1+p[0]], p[1+p[0]:]
	default:
		a, rest, ok := bytes.Cut(p, []byte{0})
		if !ok {
			return r, errMySQLShort
		}
		r.auth, p = a, rest
	}
	if r.caps&mysqlClientConnectWithDB != 0 && len(p) > 0 {
		d, rest, _ := bytes.Cut(p, []byte{0})
		r.database, p = string(d), rest
	}
	if r.caps&mysqlClientPluginAuth != 0 && len(p) > 0 {
		pl, rest, _ := bytes.Cut(p, []byte{0})
		r.plugin, p = string(pl), rest
	}
	if r.plugin == "" {
		r.plugin = mysqlPluginNative
	}
	if r.caps&mysqlClientConnectAttrs != 0 && len(p) > 0 {
		n, rest, ok := mysqlLenenc(p)
		if !ok || n > uint64(len(rest)) {
			return r, errMySQLShort
		}
		a := rest[:n]
		r.attrs = map[string]string{}
		for len(a) > 0 && len(r.attrs) < mysqlMaxAttrs {
			k, rest, ok := mysqlLenencStr(a)
			if !ok {
				break
			}
			v, rest2, ok := mysqlLenencStr(rest)
			if !ok {
				break
			}
			a = rest2
			r.attrs[k] = v
		}
	}
	return r, nil
}

// mysqlLenenc decodes a length-encoded integer, returning the remainder.
func mysqlLenenc(p []byte) (uint64, []byte, bool) {
	if len(p) == 0 {
		return 0, nil, false
	}
	var n int
	switch p[0] {
	case 0xfc:
		n = 2
	case 0xfd:
		n = 3
	case 0xfe:
		n = 8
	case 0xfb, 0xff:
		return 0, nil, false
	default:
		return uint64(p[0]), p[1:], true
	}
	if len(p) < 1+n {
		return 0, nil, false
	}
	var v uint64
	for i := n; i >= 1; i-- {
		v = v<<8 | uint64(p[i])
	}
	return v, p[1+n:], true
}

// mysqlLenencStr decodes a length-encoded string, returning the remainder.
func mysqlLenencStr(p []byte) (string, []byte, bool) {
	n, rest, ok := mysqlLenenc(p)
	if !ok || n > uint64(len(rest)) {
		return "", nil, false
	}
	return string(rest[:n]), rest[n:], true
}
