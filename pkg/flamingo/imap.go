package flamingo

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// IMAPCramChallenge is the fixed CRAM-MD5 challenge presented to every
// client. A constant challenge, like the fixed VNC and NTLM challenges,
// lets captured responses be cracked offline with precomputed material.
const IMAPCramChallenge = "<1896.flamingo@localhost>"

// imapMaxLiteral caps the size of a literal argument accepted from a client.
const imapMaxLiteral = 64 * 1024

// imapTimeout is the idle deadline applied to each client connection.
const imapTimeout = 30 * time.Second

// ConfIMAP describes the options for an IMAP capture service. The TLS flag
// selects implicit TLS (IMAPS); plaintext listeners offer STARTTLS when a
// certificate is configured.
type ConfIMAP struct {
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

// NewConfIMAP creates a default configuration for the IMAP capture server.
func NewConfIMAP() *ConfIMAP {
	return &ConfIMAP{
		BindPort: 143,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfIMAP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfIMAP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnIMAP starts a logging IMAP or IMAPS server.
func SpawnIMAP(c *ConfIMAP) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	if !c.TLS {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s (%s)", addr, err)
		}
		c.listener = listener
		log.Debugf("imap is listening on %s", addr)
		go imapStart(c)
		return nil
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return fmt.Errorf("failed to load tls cert for imaps on %s (%s)", addr, err)
	}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("imaps is listening on %s", addr)
	go imapStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfIMAP) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

func imapStart(c *ConfIMAP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go imapHandleConnection(c, conn)
	}
}

// pname returns the protocol name used in credential records.
func (c *ConfIMAP) pname() string {
	if c.TLS {
		return "imaps"
	}
	return "imap"
}

// record logs a captured credential with the given method and fields.
func (c *ConfIMAP) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", c.pname(), conn.RemoteAddr().String(), rec)
}

// imapSession tracks the state of a single client connection.
type imapSession struct {
	conf      *ConfIMAP
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	encrypted bool
}

// capabilities returns the CAPABILITY list advertised to the client. Only
// mechanisms that yield a capturable credential are offered, plus STARTTLS
// on plaintext connections that can be upgraded.
func (s *imapSession) capabilities() string {
	caps := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5"
	if s.canStartTLS() {
		caps += " STARTTLS"
	}
	return caps
}

// canStartTLS reports whether the connection can still be upgraded to TLS.
func (s *imapSession) canStartTLS() bool {
	return !s.encrypted && s.conf.TLSCert != ""
}

// reply writes a single response line to the client.
func (s *imapSession) reply(format string, args ...any) {
	fmt.Fprintf(s.writer, format+"\r\n", args...)
	s.writer.Flush()
}

// readLine reads one line from the client with the trailing CRLF removed.
func (s *imapSession) readLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// imapHandleConnection greets the client and runs the command loop until
// the client disconnects, logs out, or times out.
func imapHandleConnection(c *ConfIMAP, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(imapTimeout))

	s := &imapSession{
		conf:      c,
		conn:      conn,
		reader:    bufio.NewReader(conn),
		writer:    bufio.NewWriter(conn),
		encrypted: c.TLS,
	}
	s.reply("* OK [CAPABILITY %s] flamingo ready", s.capabilities())
	s.commandLoop()
}

// commandLoop handles tagged commands until the connection ends. Authentication
// attempts are recorded and rejected so a client will retry with any other
// credentials or mechanisms it has.
func (s *imapSession) commandLoop() {
	for {
		line, err := s.readLine()
		if err != nil {
			return
		}

		// Commands are "<tag> <command> [args]"
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			continue
		}
		tag := parts[0]
		command := strings.ToUpper(parts[1])
		args := ""
		if len(parts) == 3 {
			args = parts[2]
		}

		switch command {
		case "CAPABILITY":
			s.reply("* CAPABILITY %s", s.capabilities())
			s.reply("%s OK CAPABILITY completed", tag)

		case "NOOP":
			s.reply("%s OK NOOP completed", tag)

		case "STARTTLS":
			if !s.canStartTLS() {
				s.reply("%s NO STARTTLS not available", tag)
				continue
			}
			s.reply("%s OK begin TLS negotiation", tag)
			if err := s.startTLS(); err != nil {
				log.Debugf("imap starttls failed from %s: %s", s.conn.RemoteAddr(), err)
				return
			}

		case "LOGIN":
			fields, err := s.readAstrings(args)
			if err != nil {
				s.reply("%s BAD invalid LOGIN arguments", tag)
				continue
			}
			user, pass := "", ""
			if len(fields) > 0 {
				user = fields[0]
			}
			if len(fields) > 1 {
				pass = fields[1]
			}
			s.conf.record(s.conn, "LOGIN", map[string]string{
				"username": user,
				"password": pass,
			})
			s.reply("%s NO [AUTHENTICATIONFAILED] credentials rejected", tag)

		case "AUTHENTICATE":
			// Arguments are "<mechanism> [initial-response]"
			mechParts := strings.SplitN(strings.TrimSpace(args), " ", 2)
			mech := strings.ToUpper(mechParts[0])
			initial := ""
			if len(mechParts) == 2 {
				initial = strings.TrimSpace(mechParts[1])
			}
			var err error
			switch mech {
			case "PLAIN":
				err = s.authPlain(tag, initial)
			case "LOGIN":
				err = s.authLogin(tag, initial)
			case "CRAM-MD5":
				err = s.authCramMD5(tag)
			default:
				s.reply("%s NO unsupported mechanism", tag)
			}
			if err != nil {
				return
			}

		case "LOGOUT":
			s.reply("* BYE flamingo logging out")
			s.reply("%s OK LOGOUT completed", tag)
			return

		default:
			s.reply("%s NO authenticate first", tag)
		}
	}
}

// startTLS upgrades the connection in place. The client resumes the same
// session over TLS without a second greeting.
func (s *imapSession) startTLS() error {
	tlsConfig, err := s.conf.tlsConfig()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	tlsConn.SetDeadline(time.Now().Add(imapTimeout))
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.encrypted = true
	return nil
}

// continuation sends a server continuation request and returns the client
// response. A "*" response is a SASL cancellation and is reported as a
// base64 error so the caller rejects the attempt.
func (s *imapSession) continuation(prompt string) ([]byte, error) {
	s.reply("+ %s", prompt)
	line, err := s.readLine()
	if err != nil {
		return nil, err
	}
	if line == "*" {
		return nil, base64.CorruptInputError(0)
	}
	return base64.StdEncoding.DecodeString(line)
}

// rejectAuth reports an authentication failure or a malformed response.
func (s *imapSession) rejectAuth(tag string, err error) error {
	if _, ok := err.(base64.CorruptInputError); ok {
		s.reply("%s BAD invalid SASL response", tag)
		return nil
	}
	if err != nil {
		return err
	}
	s.reply("%s NO [AUTHENTICATIONFAILED] credentials rejected", tag)
	return nil
}

// authPlain handles SASL PLAIN. The credential arrives either as an inline
// initial response or after a continuation, decoding to
// "[authzid]\x00authcid\x00password".
func (s *imapSession) authPlain(tag, initial string) error {
	var decoded []byte
	var err error
	if initial != "" && initial != "=" {
		decoded, err = base64.StdEncoding.DecodeString(initial)
	} else {
		decoded, err = s.continuation("")
	}
	if err != nil {
		return s.rejectAuth(tag, err)
	}

	fields := strings.Split(string(decoded), "\x00")
	user, pass := "", ""
	switch len(fields) {
	case 3:
		user, pass = fields[1], fields[2]
	case 2:
		user, pass = fields[0], fields[1]
	}
	s.conf.record(s.conn, "AUTHENTICATE PLAIN", map[string]string{
		"username": user,
		"password": pass,
	})
	return s.rejectAuth(tag, nil)
}

// authLogin handles SASL LOGIN, prompting for a base64 username and password
// in turn. An inline initial response supplies the username.
func (s *imapSession) authLogin(tag, initial string) error {
	var user []byte
	var err error
	if initial != "" && initial != "=" {
		user, err = base64.StdEncoding.DecodeString(initial)
	} else {
		user, err = s.continuation(base64.StdEncoding.EncodeToString([]byte("Username:")))
	}
	if err != nil {
		return s.rejectAuth(tag, err)
	}

	pass, err := s.continuation(base64.StdEncoding.EncodeToString([]byte("Password:")))
	if err != nil {
		return s.rejectAuth(tag, err)
	}

	s.conf.record(s.conn, "AUTHENTICATE LOGIN", map[string]string{
		"username": string(user),
		"password": string(pass),
	})
	return s.rejectAuth(tag, nil)
}

// authCramMD5 handles SASL CRAM-MD5. The client returns
// HMAC-MD5(password, challenge), which is recorded in hashcat mode 10200
// format for offline cracking.
func (s *imapSession) authCramMD5(tag string) error {
	challB64 := base64.StdEncoding.EncodeToString([]byte(IMAPCramChallenge))
	decoded, err := s.continuation(challB64)
	if err != nil {
		return s.rejectAuth(tag, err)
	}

	// The decoded response is "<username> <hex-hmac-md5>"
	username, hexHMAC := string(decoded), ""
	if sp := strings.LastIndexByte(username, ' '); sp >= 0 {
		username, hexHMAC = username[:sp], username[sp+1:]
	}

	s.conf.record(s.conn, "AUTHENTICATE CRAM-MD5", map[string]string{
		"username":  username,
		"challenge": IMAPCramChallenge,
		"response":  hexHMAC,
		"hashcat":   fmt.Sprintf("$cram_md5$%s$%s", challB64, base64.StdEncoding.EncodeToString(decoded)),
	})
	return s.rejectAuth(tag, nil)
}

// readAstrings parses space-separated IMAP astring arguments from a command
// line, handling atoms, quoted strings with backslash escapes, and both
// synchronizing and non-synchronizing literals.
func (s *imapSession) readAstrings(line string) ([]string, error) {
	var fields []string
	for {
		line = strings.TrimLeft(line, " ")
		if line == "" {
			return fields, nil
		}

		switch line[0] {
		case '"':
			var sb strings.Builder
			i := 1
			for ; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				sb.WriteByte(line[i])
			}
			fields = append(fields, sb.String())
			if i < len(line) {
				i++
			}
			line = line[i:]

		case '{':
			// A literal is always the last item on its line
			end := strings.IndexByte(line, '}')
			if end < 0 || end != len(line)-1 {
				return fields, fmt.Errorf("malformed literal")
			}
			spec := line[1:end]
			nonSync := strings.HasSuffix(spec, "+")
			size, err := strconv.Atoi(strings.TrimSuffix(spec, "+"))
			if err != nil || size < 0 || size > imapMaxLiteral {
				return fields, fmt.Errorf("invalid literal size")
			}
			if !nonSync {
				s.reply("+ ready")
			}
			buf := make([]byte, size)
			if _, err := io.ReadFull(s.reader, buf); err != nil {
				return fields, err
			}
			fields = append(fields, string(buf))
			line, err = s.readLine()
			if err != nil {
				return fields, err
			}

		default:
			end := strings.IndexByte(line, ' ')
			if end < 0 {
				end = len(line)
			}
			fields = append(fields, line[:end])
			line = line[end:]
		}
	}
}
