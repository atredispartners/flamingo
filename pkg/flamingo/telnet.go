package flamingo

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// telnetTimeout is the idle deadline applied to each read from a client.
const telnetTimeout = 30 * time.Second

// Telnet session limits.
const (
	telnetMaxAttempts = 3
	telnetMaxLine     = 256
	telnetMaxEmpty    = 8
	telnetMaxReplies  = 32
	telnetMaxTerm     = 64
)

// Telnet banner and prompts, matching BusyBox telnetd running login on a
// device with no hostname set.
const (
	telnetBanner         = "\r\n"
	telnetLoginPrompt    = "login: "
	telnetPasswordPrompt = "Password: "
	telnetLoginFailed    = "\r\nLogin incorrect\r\n"
)

// Telnet command and option bytes.
const (
	telnetSE   = 240
	telnetSB   = 250
	telnetWILL = 251
	telnetWONT = 252
	telnetDO   = 253
	telnetDONT = 254
	telnetIAC  = 255

	telnetOptEcho     = 1
	telnetOptSGA      = 3
	telnetOptTermType = 24

	telnetTermTypeIs   = 0
	telnetTermTypeSend = 1
)

// Parser states for telnetSession.readLine.
const (
	telnetStNormal = iota
	telnetStIAC
	telnetStOption
	telnetStSub
	telnetStSubIAC
)

// ConfTelnet holds information for a Telnet server.
type ConfTelnet struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfTelnet creates a default configuration for the Telnet capture server.
func NewConfTelnet() *ConfTelnet {
	return &ConfTelnet{
		BindPort: 23,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfTelnet) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfTelnet) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnTelnet starts a logging Telnet server.
func SpawnTelnet(c *ConfTelnet) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("telnet is listening on %s", addr)
	go telnetStart(c)
	return nil
}

// telnetStart accepts client connections until the service shuts down.
func telnetStart(c *ConfTelnet) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go telnetHandleConnection(c, conn)
	}
}

// record logs a captured login attempt, including the terminal type when known.
func (c *ConfTelnet) record(conn net.Conn, user, pass, terminal string) {
	rec := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"username": user,
		"password": pass,
	}
	if terminal != "" {
		rec["terminal"] = terminal
	}
	c.RecordWriter.Record("credential", "telnet", conn.RemoteAddr().String(), rec)
}

// telnetSession tracks the state of a single client connection.
type telnetSession struct {
	conf     *ConfTelnet
	conn     net.Conn
	reader   *bufio.Reader
	replies  int
	terminal string
	afterCR  bool
}

// telnetHandleConnection negotiates options, presents the login prompt, and
// records each username and password pair until the attempt limit is reached.
func telnetHandleConnection(c *ConfTelnet, conn net.Conn) {
	defer conn.Close()
	s := &telnetSession{
		conf:   c,
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
	s.serve()
}

// serve runs the login loop. Every attempt is recorded and refused.
func (s *telnetSession) serve() {
	hello := []byte{
		telnetIAC, telnetWILL, telnetOptEcho,
		telnetIAC, telnetWILL, telnetOptSGA,
		telnetIAC, telnetDO, telnetOptTermType,
	}
	if !s.write(append(hello, telnetBanner...)) {
		return
	}
	for attempts, empty := 0, 0; attempts < telnetMaxAttempts && empty < telnetMaxEmpty; {
		if !s.write([]byte(telnetLoginPrompt)) {
			return
		}
		line, err := s.readLine(telnetMaxLine)
		if err != nil {
			return
		}
		user := telnetEscape(line, telnetMaxLine)
		if user == "" {
			empty++
			continue
		}
		if !s.write([]byte(user + "\r\n" + telnetPasswordPrompt)) {
			return
		}
		line, err = s.readLine(telnetMaxLine)
		if err != nil {
			return
		}
		pass := telnetEscape(line, telnetMaxLine)
		attempts++
		s.conf.record(s.conn, user, pass, s.terminal)
		if !s.write([]byte(telnetLoginFailed)) {
			return
		}
	}
}

// readLine returns the next line with telnet commands stripped, keeping at
// most max bytes of it. Lines end with CR LF, CR NUL, bare CR, or bare LF.
func (s *telnetSession) readLine(max int) ([]byte, error) {
	var line, sub []byte
	state := telnetStNormal
	var cmd byte
	for {
		s.conn.SetReadDeadline(time.Now().Add(telnetTimeout))
		b, err := s.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		switch state {
		case telnetStNormal:
			switch {
			case b == telnetIAC:
				state = telnetStIAC
			case b == '\n' || b == '\r':
				if b == '\n' && s.afterCR {
					s.afterCR = false
					continue
				}
				s.afterCR = b == '\r'
				return line, nil
			case b == 0 && s.afterCR:
				s.afterCR = false
			default:
				s.afterCR = false
				if len(line) < max {
					line = append(line, b)
				}
			}
		case telnetStIAC:
			switch b {
			case telnetIAC:
				state = telnetStNormal
				if len(line) < max {
					line = append(line, b)
				}
			case telnetWILL, telnetWONT, telnetDO, telnetDONT:
				cmd, state = b, telnetStOption
			case telnetSB:
				sub, state = sub[:0], telnetStSub
			default:
				state = telnetStNormal
			}
		case telnetStOption:
			state = telnetStNormal
			if !s.negotiate(cmd, b) {
				return nil, net.ErrClosed
			}
		case telnetStSub:
			if b == telnetIAC {
				state = telnetStSubIAC
			} else if len(sub) < telnetMaxLine {
				sub = append(sub, b)
			}
		case telnetStSubIAC:
			switch b {
			case telnetIAC:
				state = telnetStSub
				if len(sub) < telnetMaxLine {
					sub = append(sub, b)
				}
			case telnetSE:
				state = telnetStNormal
				s.subnegotiation(sub)
			default:
				state = telnetStSub
			}
		}
	}
}

// negotiate answers a WILL/WONT/DO/DONT and reports whether the write
// succeeded. Options the server announced itself need no answer, a client
// offering TERMINAL-TYPE is asked for it, and anything else is declined.
func (s *telnetSession) negotiate(cmd, opt byte) bool {
	if s.replies >= telnetMaxReplies {
		return true
	}
	var reply []byte
	switch cmd {
	case telnetWILL:
		if opt == telnetOptTermType {
			reply = []byte{telnetIAC, telnetSB, telnetOptTermType, telnetTermTypeSend, telnetIAC, telnetSE}
		} else {
			reply = []byte{telnetIAC, telnetDONT, opt}
		}
	case telnetDO:
		if opt != telnetOptEcho && opt != telnetOptSGA {
			reply = []byte{telnetIAC, telnetWONT, opt}
		}
	}
	if reply == nil {
		return true
	}
	s.replies++
	return s.write(reply)
}

// subnegotiation keeps the first TERMINAL-TYPE IS answer from the client.
func (s *telnetSession) subnegotiation(sub []byte) {
	if len(sub) >= 3 && sub[0] == telnetOptTermType && sub[1] == telnetTermTypeIs && s.terminal == "" {
		s.terminal = telnetEscape(sub[2:], telnetMaxTerm)
	}
}

// write sends bytes to the client and reports whether the write succeeded.
func (s *telnetSession) write(b []byte) bool {
	s.conn.SetWriteDeadline(time.Now().Add(telnetTimeout))
	_, err := s.conn.Write(b)
	return err == nil
}

// telnetEscape returns at most n bytes of b as printable text, escaping
// backslashes, control characters, and non-ASCII bytes.
func telnetEscape(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}
