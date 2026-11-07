package flamingo

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// POP3CramChallenge is the fixed challenge used for both the APOP timestamp in
// the greeting and the CRAM-MD5 challenge. A constant challenge lets captured
// digests and HMACs be cracked offline with precomputed material.
const POP3CramChallenge = "<1896.flamingo@localhost>"

// pop3Timeout is the idle deadline applied to each client connection.
const pop3Timeout = 30 * time.Second

// ConfPOP3 describes the options for a POP3 capture service. The TLS flag
// selects implicit TLS (POP3S); plaintext listeners offer STLS when a
// certificate is configured.
type ConfPOP3 struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	TLS          bool
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfPOP3 creates a default configuration for the POP3 capture server.
func NewConfPOP3() *ConfPOP3 {
	return &ConfPOP3{
		BindPort: 110,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfPOP3) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfPOP3) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnPOP3 starts a logging POP3 or POP3S server.
func SpawnPOP3(c *ConfPOP3) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	if !c.TLS {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s (%s)", addr, err)
		}
		c.listener = listener
		log.Debugf("pop3 is listening on %s", addr)
		go pop3Start(c)
		return nil
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return fmt.Errorf("failed to load tls cert for pop3s on %s (%s)", addr, err)
	}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("pop3s is listening on %s", addr)
	go pop3Start(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfPOP3) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

// pop3Start accepts connections until the service is shut down.
func pop3Start(c *ConfPOP3) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go pop3HandleConnection(c, conn)
	}
}

// pname returns the protocol name used in credential records.
func (c *ConfPOP3) pname() string {
	if c.TLS {
		return "pop3s"
	}
	return "pop3"
}

// record logs a captured credential with the given method and fields.
func (c *ConfPOP3) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", c.pname(), conn.RemoteAddr().String(), rec)
}

// pop3Session tracks the state of a single client connection.
type pop3Session struct {
	conf      *ConfPOP3
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	encrypted bool
	user      string
}

// canStartTLS reports whether the connection can still be upgraded to TLS.
func (s *pop3Session) canStartTLS() bool {
	return !s.encrypted && s.conf.TLSCert != ""
}

// reply writes a single response line to the client.
func (s *pop3Session) reply(format string, args ...any) {
	fmt.Fprintf(s.writer, format+"\r\n", args...)
	s.writer.Flush()
}

// readLine reads one line from the client with the trailing CRLF removed,
// refreshing the idle deadline first.
func (s *pop3Session) readLine() (string, error) {
	s.conn.SetDeadline(time.Now().Add(pop3Timeout))
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// pop3HandleConnection greets the client with a Dovecot-style banner carrying
// the APOP timestamp and runs the command loop until the client disconnects,
// quits, or times out.
func pop3HandleConnection(c *ConfPOP3, conn net.Conn) {
	defer conn.Close()

	s := &pop3Session{
		conf:      c,
		conn:      conn,
		reader:    bufio.NewReader(conn),
		writer:    bufio.NewWriter(conn),
		encrypted: c.TLS,
	}
	s.reply("+OK Dovecot (Ubuntu) ready. %s", POP3CramChallenge)
	s.commandLoop()
}

// capabilities returns the CAPA response lines. Only mechanisms that yield a
// capturable credential are offered, plus STLS on plaintext connections that
// can be upgraded.
func (s *pop3Session) capabilities() []string {
	caps := []string{"CAPA", "TOP", "UIDL", "RESP-CODES", "PIPELINING", "AUTH-RESP-CODE"}
	if s.canStartTLS() {
		caps = append(caps, "STLS")
	}
	return append(caps, "USER", "SASL PLAIN LOGIN CRAM-MD5")
}

// commandLoop handles commands until the connection ends. Authentication
// attempts are recorded and rejected so a client will retry with any other
// credentials or mechanisms it has.
func (s *pop3Session) commandLoop() {
	for {
		line, err := s.readLine()
		if err != nil {
			return
		}

		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(strings.TrimSpace(verb))
		arg = strings.TrimSpace(arg)
		if verb == "" {
			continue
		}

		switch verb {
		case "CAPA":
			s.reply("+OK")
			for _, c := range s.capabilities() {
				s.reply("%s", c)
			}
			s.reply(".")

		case "USER":
			s.user = arg
			s.reply("+OK")

		case "PASS":
			s.conf.record(s.conn, "USER/PASS", map[string]string{
				"username": s.user,
				"password": arg,
			})
			s.reply("-ERR [AUTH] Authentication failed.")

		case "APOP":
			name, digest, _ := strings.Cut(arg, " ")
			s.apop(name, strings.TrimSpace(digest))
			s.reply("-ERR [AUTH] Authentication failed.")

		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			mech = strings.ToUpper(mech)
			initial = strings.TrimSpace(initial)
			if mech == "" {
				s.reply("+OK")
				s.reply("PLAIN")
				s.reply("LOGIN")
				s.reply("CRAM-MD5")
				s.reply(".")
				continue
			}
			var err error
			switch mech {
			case "PLAIN":
				err = s.authPlain(initial)
			case "LOGIN":
				err = s.authLogin(initial)
			case "CRAM-MD5":
				err = s.authCramMD5()
			default:
				s.reply("-ERR Unsupported authentication mechanism.")
			}
			if err != nil {
				return
			}

		case "STLS":
			if !s.canStartTLS() {
				s.reply("-ERR TLS not available.")
				continue
			}
			s.reply("+OK Begin TLS negotiation now.")
			if err := s.startTLS(); err != nil {
				log.Debugf("pop3 stls failed from %s: %s", s.conn.RemoteAddr(), err)
				return
			}

		case "NOOP":
			s.reply("+OK")

		case "QUIT":
			s.reply("+OK Logging out.")
			return

		default:
			s.reply("-ERR Unknown command.")
		}
	}
}

// startTLS upgrades the connection in place. The client resumes the same
// session over TLS without a second greeting.
func (s *pop3Session) startTLS() error {
	tlsConfig, err := s.conf.tlsConfig()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.encrypted = true
	return nil
}

// apop records an APOP login, where the digest is MD5 of the greeting
// timestamp concatenated with the password. The hashcat field is in mode 20
// (md5($salt.$pass)) form.
func (s *pop3Session) apop(user, digest string) {
	s.conf.record(s.conn, "APOP", map[string]string{
		"username":  user,
		"challenge": POP3CramChallenge,
		"response":  digest,
		"hashcat":   fmt.Sprintf("%s:%s", digest, POP3CramChallenge),
	})
}

// continuation sends a server continuation request and returns the client
// response. A "*" response is a SASL cancellation and is reported as a
// base64 error so the caller rejects the attempt.
func (s *pop3Session) continuation(prompt string) ([]byte, error) {
	s.reply("+ %s", prompt)
	line, err := s.readLine()
	if err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	if line == "*" {
		return nil, base64.CorruptInputError(0)
	}
	return base64.StdEncoding.DecodeString(line)
}

// rejectAuth reports an authentication failure or a malformed response.
func (s *pop3Session) rejectAuth(err error) error {
	if _, ok := err.(base64.CorruptInputError); ok {
		s.reply("-ERR Invalid base64 data in continued response.")
		return nil
	}
	if err != nil {
		return err
	}
	s.reply("-ERR [AUTH] Authentication failed.")
	return nil
}

// authPlain handles SASL PLAIN. The credential arrives either as an inline
// initial response or after a continuation, decoding to
// "[authzid]\x00authcid\x00password".
func (s *pop3Session) authPlain(initial string) error {
	var decoded []byte
	var err error
	if initial != "" && initial != "=" {
		decoded, err = base64.StdEncoding.DecodeString(initial)
	} else {
		decoded, err = s.continuation("")
	}
	if err != nil {
		return s.rejectAuth(err)
	}

	fields := strings.Split(string(decoded), "\x00")
	user, pass := "", ""
	switch len(fields) {
	case 3:
		user, pass = fields[1], fields[2]
	case 2:
		user, pass = fields[0], fields[1]
	}
	s.conf.record(s.conn, "AUTH PLAIN", map[string]string{
		"username": user,
		"password": pass,
	})
	return s.rejectAuth(nil)
}

// authLogin handles SASL LOGIN, prompting for a base64 username and password
// in turn. An inline initial response supplies the username.
func (s *pop3Session) authLogin(initial string) error {
	var user []byte
	var err error
	if initial != "" && initial != "=" {
		user, err = base64.StdEncoding.DecodeString(initial)
	} else {
		user, err = s.continuation(base64.StdEncoding.EncodeToString([]byte("Username:")))
	}
	if err != nil {
		return s.rejectAuth(err)
	}

	pass, err := s.continuation(base64.StdEncoding.EncodeToString([]byte("Password:")))
	if err != nil {
		return s.rejectAuth(err)
	}

	s.conf.record(s.conn, "AUTH LOGIN", map[string]string{
		"username": string(user),
		"password": string(pass),
	})
	return s.rejectAuth(nil)
}

// authCramMD5 handles SASL CRAM-MD5. The client returns
// HMAC-MD5(password, challenge), which is recorded in hashcat mode 10200
// format for offline cracking.
func (s *pop3Session) authCramMD5() error {
	challB64 := base64.StdEncoding.EncodeToString([]byte(POP3CramChallenge))
	decoded, err := s.continuation(challB64)
	if err != nil {
		return s.rejectAuth(err)
	}

	// The decoded response is "<username> <hex-hmac-md5>"
	username, hexHMAC := string(decoded), ""
	if sp := strings.LastIndexByte(username, ' '); sp >= 0 {
		username, hexHMAC = username[:sp], username[sp+1:]
	}

	s.conf.record(s.conn, "AUTH CRAM-MD5", map[string]string{
		"username":  username,
		"challenge": POP3CramChallenge,
		"response":  hexHMAC,
		"hashcat":   fmt.Sprintf("$cram_md5$%s$%s", challB64, base64.StdEncoding.EncodeToString(decoded)),
	})
	return s.rejectAuth(nil)
}
