package flamingo

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfIMAP describes the options for an IMAP capture service. A single
// config serves either plaintext IMAP (port 143) or implicit-TLS IMAPS
// (port 993) depending on the TLS flag, mirroring the LDAP/LDAPS split.
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

// SpawnIMAP starts a logging IMAP server.
func SpawnIMAP(c *ConfIMAP) error {
	if !c.TLS {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
		if err != nil {
			return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
		}
		c.listener = listener
		go imapStart(c)
		return nil
	}

	tlsConfig := tls.Config{ServerName: c.TLSName}
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return fmt.Errorf("failed to load tls cert for imaps on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	tlsConfig.Certificates = []tls.Certificate{kp}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort), &tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener
	go imapStart(c)
	return nil
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

func (c *ConfIMAP) pname() string {
	if c.TLS {
		return "imaps"
	}
	return "imap"
}

// imapRecord logs a captured credential.
func (c *ConfIMAP) imapRecord(conn net.Conn, username, password, method string) {
	c.RecordWriter.Record(
		"credential",
		c.pname(),
		conn.RemoteAddr().String(),
		map[string]string{
			"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"username": username,
			"password": password,
			"method":   method,
		},
	)
}

// imapCapabilities returns the CAPABILITY list flamingo advertises. It
// offers the mechanisms it can capture (LOGIN/PLAIN cleartext and CRAM-MD5
// as a crackable fallback) and, on a not-yet-encrypted plaintext
// connection, STARTTLS so a client that refuses to send credentials in the
// clear will upgrade and then authenticate.
func imapCapabilities(encrypted bool) string {
	caps := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5"
	if !encrypted {
		caps += " STARTTLS"
	}
	return caps
}

// imapHandleConnection walks a client through enough of the IMAP
// conversation to capture credentials. It advertises LOGIN, PLAIN,
// CRAM-MD5 and (on plaintext connections) STARTTLS so a client will
// attempt one of them.
func imapHandleConnection(c *ConfIMAP, conn net.Conn) {
	defer conn.Close()
	// Encrypted from the start on an implicit-TLS (993) listener.
	imapConverse(c, conn, c.TLS)
}

// imapConverse greets the client once and then runs the command loop.
// encrypted tracks whether the connection is already under TLS (implicit
// TLS), which controls whether STARTTLS is advertised.
func imapConverse(c *ConfIMAP, conn net.Conn, encrypted bool) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writer.WriteString(fmt.Sprintf("* OK [CAPABILITY %s] flamingo ready\r\n", imapCapabilities(encrypted)))
	writer.Flush()

	imapCommandLoop(c, conn, reader, writer, encrypted)
}

// imapCommandLoop reads and handles commands on an already-greeted
// connection. After a STARTTLS upgrade it is re-entered over the new TLS
// connection WITHOUT sending a second greeting, as RFC 3501 requires: the
// client continues the same session and does not expect another greeting.
func imapCommandLoop(c *ConfIMAP, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, encrypted bool) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		// IMAP commands are "<tag> <command> [args]".
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
			writer.WriteString(fmt.Sprintf("* CAPABILITY %s\r\n", imapCapabilities(encrypted)))
			writer.WriteString(fmt.Sprintf("%s OK CAPABILITY completed\r\n", tag))
			writer.Flush()

		case "STARTTLS":
			if encrypted || c.TLSCert == "" {
				writer.WriteString(fmt.Sprintf("%s NO STARTTLS not available\r\n", tag))
				writer.Flush()
				continue
			}
			writer.WriteString(fmt.Sprintf("%s OK begin TLS negotiation\r\n", tag))
			writer.Flush()

			kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
			if err != nil {
				log.Debugf("imap starttls cert error: %s", err)
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{kp},
				ServerName:   c.TLSName,
			})
			if err := tlsConn.Handshake(); err != nil {
				log.Debugf("imap starttls handshake failed from %s: %s", conn.RemoteAddr(), err)
				return
			}
			// Continue the SAME session over TLS. No second greeting: the
			// client resumes sending commands on the encrypted channel.
			tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
			imapCommandLoop(c, tlsConn, bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn), true)
			return

		case "LOGIN":
			// LOGIN <user> <pass>, each possibly quoted.
			user, pass := imapParseLogin(args)
			c.imapRecord(conn, user, pass, "LOGIN")
			writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] credentials rejected\r\n", tag))
			writer.Flush()

		case "AUTHENTICATE":
			// args is "<mechanism> [initial-response]". A client may send
			// the SASL initial response inline rather than waiting for the
			// server's continuation prompt.
			mechParts := strings.SplitN(strings.TrimSpace(args), " ", 2)
			mech := strings.ToUpper(mechParts[0])
			initial := ""
			if len(mechParts) == 2 {
				initial = strings.TrimSpace(mechParts[1])
			}
			switch mech {
			case "PLAIN":
				if imapAuthPlain(c, conn, reader, writer, tag, initial) {
					return
				}
			case "LOGIN":
				if imapAuthLogin(c, conn, reader, writer, tag, initial) {
					return
				}
			case "CRAM-MD5":
				if imapAuthCramMD5(c, conn, reader, writer, tag) {
					return
				}
			default:
				writer.WriteString(fmt.Sprintf("%s NO unsupported mechanism\r\n", tag))
				writer.Flush()
			}

		case "LOGOUT":
			writer.WriteString("* BYE flamingo logging out\r\n")
			writer.WriteString(fmt.Sprintf("%s OK LOGOUT completed\r\n", tag))
			writer.Flush()
			return

		default:
			// Nudge the client toward authenticating.
			writer.WriteString(fmt.Sprintf("%s NO authenticate first\r\n", tag))
			writer.Flush()
		}
	}
}

// imapAuthPlain handles SASL PLAIN. The credential may be sent inline as a
// SASL initial response ("AUTHENTICATE PLAIN <base64>") or after a
// continuation prompt. The decoded blob is "[authzid]\0authcid\0password".
func imapAuthPlain(c *ConfIMAP, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, tag, initial string) bool {
	resp := initial
	if resp == "" {
		// No inline initial response; prompt for it.
		writer.WriteString("+ \r\n")
		writer.Flush()
		line, err := reader.ReadString('\n')
		if err != nil {
			return true
		}
		resp = strings.TrimRight(line, "\r\n")
	}

	decoded, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		writer.WriteString(fmt.Sprintf("%s NO invalid base64\r\n", tag))
		writer.Flush()
		return false
	}

	// Split on NUL: [authzid] NUL authcid NUL password
	fields := strings.Split(string(decoded), "\x00")
	user, pass := "", ""
	if len(fields) == 3 {
		user = fields[1]
		pass = fields[2]
	} else if len(fields) == 2 {
		user = fields[0]
		pass = fields[1]
	}
	c.imapRecord(conn, user, pass, "AUTHENTICATE PLAIN")
	writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] credentials rejected\r\n", tag))
	writer.Flush()
	return true
}

// imapAuthLogin handles SASL LOGIN: the server base64-prompts for the
// username, then the password, each sent base64-encoded by the client. A
// client may supply the (base64) username inline as a SASL initial
// response, in which case the Username prompt is skipped.
func imapAuthLogin(c *ConfIMAP, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, tag, initial string) bool {
	var user []byte
	if initial != "" {
		user, _ = base64.StdEncoding.DecodeString(initial)
	} else {
		// Prompt "Username:" (base64).
		writer.WriteString("+ " + base64.StdEncoding.EncodeToString([]byte("Username:")) + "\r\n")
		writer.Flush()
		userResp, err := reader.ReadString('\n')
		if err != nil {
			return true
		}
		user, _ = base64.StdEncoding.DecodeString(strings.TrimRight(userResp, "\r\n"))
	}

	// Prompt "Password:" (base64).
	writer.WriteString("+ " + base64.StdEncoding.EncodeToString([]byte("Password:")) + "\r\n")
	writer.Flush()
	passResp, err := reader.ReadString('\n')
	if err != nil {
		return true
	}
	pass, _ := base64.StdEncoding.DecodeString(strings.TrimRight(passResp, "\r\n"))

	c.imapRecord(conn, string(user), string(pass), "AUTHENTICATE LOGIN")
	writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] credentials rejected\r\n", tag))
	writer.Flush()
	return true
}

// IMAPCramChallenge is the fixed CRAM-MD5 challenge presented to every
// client. As with the fixed VNC and NTLM challenges, a constant challenge
// lets the captured HMAC be cracked offline with precomputed material.
// RFC 2195 challenges are formatted like a message-id; this one is
// arbitrary but constant.
const IMAPCramChallenge = "<1896.flamingo@localhost>"

// imapAuthCramMD5 handles SASL CRAM-MD5. The password itself never crosses
// the wire: the client returns HMAC-MD5(password, challenge). flamingo
// captures the username and that HMAC, which is crackable offline
// (hashcat mode 10200). The server sends a base64 challenge, and the client
// replies with base64("<username> <hex-hmac>").
func imapAuthCramMD5(c *ConfIMAP, conn net.Conn, reader *bufio.Reader, writer *bufio.Writer, tag string) bool {
	// Send the base64-encoded challenge as a continuation.
	challB64 := base64.StdEncoding.EncodeToString([]byte(IMAPCramChallenge))
	writer.WriteString("+ " + challB64 + "\r\n")
	writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		return true
	}
	resp = strings.TrimRight(resp, "\r\n")

	decoded, err := base64.StdEncoding.DecodeString(resp)
	if err != nil {
		writer.WriteString(fmt.Sprintf("%s NO invalid base64\r\n", tag))
		writer.Flush()
		return false
	}

	// Decoded form: "<username> <hex-hmac-md5>".
	username, hexHMAC := "", ""
	if sp := strings.LastIndexByte(string(decoded), ' '); sp >= 0 {
		username = string(decoded[:sp])
		hexHMAC = string(decoded[sp+1:])
	} else {
		username = string(decoded)
	}

	// hashcat mode 10200 format: $cram_md5$<base64 challenge>$<base64 response>
	// where the response is base64("<username> <hex-hmac>"), i.e. the raw
	// value the client sent.
	hashcat := fmt.Sprintf("$cram_md5$%s$%s", challB64, resp)

	c.RecordWriter.Record(
		"credential",
		c.pname(),
		conn.RemoteAddr().String(),
		map[string]string{
			"_server":   fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"username":  username,
			"challenge": IMAPCramChallenge,
			"response":  hexHMAC,
			"hashcat":   hashcat,
			"method":    "AUTHENTICATE CRAM-MD5",
		},
	)
	writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] credentials rejected\r\n", tag))
	writer.Flush()
	return true
}

// imapParseLogin parses "LOGIN user pass" arguments, stripping optional
// surrounding double quotes from each.
func imapParseLogin(args string) (string, string) {
	user, pass := "", ""
	fields := imapSplitArgs(args)
	if len(fields) >= 1 {
		user = fields[0]
	}
	if len(fields) >= 2 {
		pass = fields[1]
	}
	return user, pass
}

// imapSplitArgs splits a LOGIN argument string into fields, honoring simple
// double-quoted strings so a password containing spaces stays intact.
func imapSplitArgs(s string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}
