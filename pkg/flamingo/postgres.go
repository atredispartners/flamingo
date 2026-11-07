package flamingo

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// PostgreSQL startup request codes.
const (
	pgCodeCancel = 80877102
	pgCodeSSL    = 80877103
	pgCodeGSS    = 80877104
)

const (
	// pgMaxStartup is the server's own limit for a startup packet.
	pgMaxStartup = 10000
	// pgMaxMessage caps the size of a password message.
	pgMaxMessage = 4096
	// pgMaxParams caps the number of startup parameters parsed.
	pgMaxParams = 64
	// pgMaxRequests limits SSLRequest/GSSENCRequest round trips before the
	// startup packet.
	pgMaxRequests = 4
	// pgTimeout is the idle deadline applied to each client connection.
	pgTimeout = 30 * time.Second
)

// ConfPostgres describes the options for a PostgreSQL capture service. When
// a TLS certificate is configured an SSLRequest is accepted and the
// connection is upgraded in place; otherwise it is refused and the client
// may continue in plaintext.
type ConfPostgres struct {
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

// NewConfPostgres creates a default configuration for the PostgreSQL capture server.
func NewConfPostgres() *ConfPostgres {
	return &ConfPostgres{
		BindPort: 5432,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfPostgres) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfPostgres) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnPostgres starts a logging PostgreSQL server.
func SpawnPostgres(c *ConfPostgres) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	if c.TLSCert != "" {
		if _, err := c.tlsConfig(); err != nil {
			return fmt.Errorf("failed to load tls cert for postgres on %s (%s)", addr, err)
		}
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("postgres is listening on %s", addr)
	go pgStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfPostgres) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

func pgStart(c *ConfPostgres) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go pgHandleConnection(c, conn)
	}
}

// record logs a captured credential with the given method and fields.
func (c *ConfPostgres) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", "postgres", conn.RemoteAddr().String(), rec)
}

// pgSession tracks the state of a single client connection.
type pgSession struct {
	conf      *ConfPostgres
	conn      net.Conn
	encrypted bool
}

// write sends raw bytes to the client.
func (s *pgSession) write(b []byte) error {
	_, err := s.conn.Write(b)
	return err
}

// startTLS upgrades the connection in place after an accepted SSLRequest.
func (s *pgSession) startTLS() error {
	tlsConfig, err := s.conf.tlsConfig()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	tlsConn.SetDeadline(time.Now().Add(pgTimeout))
	s.conn = tlsConn
	s.encrypted = true
	return nil
}

// readStartup handles SSLRequest, GSSENCRequest and CancelRequest packets
// and returns the protocol code and body of the startup message.
func (s *pgSession) readStartup() (uint32, []byte, error) {
	for i := 0; i < pgMaxRequests; i++ {
		var hdr [8]byte
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return 0, nil, err
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		code := binary.BigEndian.Uint32(hdr[4:])
		if n < 8 || n > pgMaxStartup {
			return 0, nil, fmt.Errorf("bad startup length %d", n)
		}
		body := make([]byte, n-8)
		if _, err := io.ReadFull(s.conn, body); err != nil {
			return 0, nil, err
		}
		switch code {
		case pgCodeSSL:
			if s.encrypted || s.conf.TLSCert == "" {
				if err := s.write([]byte{'N'}); err != nil {
					return 0, nil, err
				}
				continue
			}
			if err := s.write([]byte{'S'}); err != nil {
				return 0, nil, err
			}
			if err := s.startTLS(); err != nil {
				return 0, nil, err
			}
			continue
		case pgCodeGSS:
			if err := s.write([]byte{'N'}); err != nil {
				return 0, nil, err
			}
			continue
		case pgCodeCancel:
			return 0, nil, fmt.Errorf("cancel request")
		}
		return code, body, nil
	}
	return 0, nil, fmt.Errorf("too many negotiation requests")
}

// pgHandleConnection reads the startup message, asks for a cleartext
// password, records it, and rejects the login with the normal 28P01 error.
func pgHandleConnection(c *ConfPostgres, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(pgTimeout))
	s := &pgSession{conf: c, conn: conn}

	code, body, err := s.readStartup()
	if err != nil {
		log.Debugf("postgres startup failed from %s: %s", conn.RemoteAddr(), err)
		return
	}
	major, minor := code>>16, code&0xffff
	if major != 3 {
		s.write(pgErrorResponse("0A000", fmt.Sprintf("unsupported frontend protocol %d.%d: server supports 3.0 to 3.0", major, minor), "postmaster.c", "2205", "ProcessStartupPacket"))
		return
	}

	params := pgParseParams(body)
	user := params["user"]
	if user == "" {
		s.write(pgErrorResponse("28000", "no PostgreSQL user name specified in startup packet", "backend_startup.c", "752", "ProcessStartupPacket"))
		return
	}

	// Newer minor versions and _pq_ options expect NegotiateProtocolVersion
	var pqOpts []string
	for k := range params {
		if strings.HasPrefix(k, "_pq_") {
			pqOpts = append(pqOpts, k)
		}
	}
	if minor > 0 || len(pqOpts) > 0 {
		if err := s.write(pgNegotiateVersion(pqOpts)); err != nil {
			return
		}
	}

	// AuthenticationCleartextPassword
	if err := s.write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}); err != nil {
		return
	}

	var hdr [5]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if hdr[0] != 'p' || n < 4 || n > pgMaxMessage {
		return
	}
	msg := make([]byte, n-4)
	if _, err := io.ReadFull(s.conn, msg); err != nil {
		return
	}
	password, _, _ := bytes.Cut(msg, []byte{0})

	fields := map[string]string{
		"username": user,
		"database": params["database"],
		"password": string(password),
	}
	for _, k := range []string{"application_name", "client_encoding"} {
		if v := params[k]; v != "" {
			fields[k] = v
		}
	}
	c.record(s.conn, "cleartext", fields)

	s.write(pgErrorResponse("28P01", fmt.Sprintf("password authentication failed for user %q", user), "auth.c", "323", "auth_failed"))
}

// pgParseParams decodes the startup parameter list of name/value C strings
// ending in an empty name.
func pgParseParams(b []byte) map[string]string {
	params := map[string]string{}
	for len(b) > 0 && len(params) < pgMaxParams {
		k, rest, ok := bytes.Cut(b, []byte{0})
		if !ok || len(k) == 0 {
			break
		}
		v, rest2, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			break
		}
		b = rest2
		params[string(k)] = string(v)
	}
	return params
}

// pgNegotiateVersion builds NegotiateProtocolVersion for a server that
// speaks 3.0 only, listing the _pq_ options it does not recognize.
func pgNegotiateVersion(opts []string) []byte {
	b := []byte{'v', 0, 0, 0, 0}
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, uint32(len(opts)))
	for _, o := range opts {
		b = append(b, o...)
		b = append(b, 0)
	}
	binary.BigEndian.PutUint32(b[1:5], uint32(len(b)-1))
	return b
}

// pgErrorResponse builds a FATAL ErrorResponse with the fields a real
// server includes.
func pgErrorResponse(code, msg, file, line, routine string) []byte {
	b := []byte{'E', 0, 0, 0, 0}
	for _, f := range []struct {
		t byte
		v string
	}{{'S', "FATAL"}, {'V', "FATAL"}, {'C', code}, {'M', msg}, {'F', file}, {'L', line}, {'R', routine}} {
		b = append(b, f.t)
		b = append(b, f.v...)
		b = append(b, 0)
	}
	b = append(b, 0)
	binary.BigEndian.PutUint32(b[1:5], uint32(len(b)-1))
	return b
}
