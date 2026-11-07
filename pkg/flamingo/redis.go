package flamingo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Limits applied to RESP parsing and to a single client session.
const (
	redisMaxArgs     = 64
	redisMaxBulk     = 8 << 10
	redisMaxLine     = 4 << 10
	redisMaxCommands = 64
	redisTimeout     = 30 * time.Second
)

// Canned replies for an unauthenticated Redis server.
const (
	redisErrWrongPass = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	redisErrNoAuth    = "-NOAUTH Authentication required.\r\n"
	redisErrHelloAuth = "-NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO <proto> AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version at the same time\r\n"
)

// errRedisProto marks a malformed RESP request.
var errRedisProto = errors.New("protocol error")

// ConfRedis holds the configuration for a Redis capture server.
type ConfRedis struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfRedis creates a default configuration for the Redis capture server.
func NewConfRedis() *ConfRedis {
	return &ConfRedis{
		BindPort: 6379,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfRedis) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfRedis) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnRedis creates a new Redis capture server.
func SpawnRedis(c *ConfRedis) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("redis is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go redisStart(c)
	return nil
}

func redisStart(c *ConfRedis) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go redisHandleConnection(c, conn)
	}
}

// redisSession tracks the state of a single client connection.
type redisSession struct {
	conf   *ConfRedis
	conn   net.Conn
	reader *bufio.Reader
	client map[string]string
}

// redisHandleConnection answers commands as a password-protected server
// would: AUTH is refused with WRONGPASS and everything else with NOAUTH,
// so a client will keep offering credentials until it gives up.
func redisHandleConnection(c *ConfRedis, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(redisTimeout))

	s := &redisSession{
		conf:   c,
		conn:   conn,
		reader: bufio.NewReader(conn),
		client: map[string]string{},
	}
	for range redisMaxCommands {
		args, err := redisReadCommand(s.reader)
		if err != nil {
			if errors.Is(err, errRedisProto) {
				s.reply("-ERR Protocol error: " + strings.TrimPrefix(err.Error(), errRedisProto.Error()+": ") + "\r\n")
			}
			return
		}
		if len(args) == 0 {
			continue
		}
		if !s.handle(strings.ToUpper(args[0]), args) {
			return
		}
	}
}

// handle answers one command and reports whether the session continues.
func (s *redisSession) handle(name string, args []string) bool {
	switch name {
	case "AUTH":
		switch len(args) {
		case 2:
			s.record("default", args[1])
		case 3:
			s.record(args[1], args[2])
		default:
			return s.reply("-ERR wrong number of arguments for 'auth' command\r\n")
		}
		return s.reply(redisErrWrongPass)
	case "HELLO":
		return s.hello(args)
	case "CLIENT":
		if len(args) >= 3 {
			switch strings.ToUpper(args[1]) {
			case "SETNAME":
				s.client["client_name"] = args[2]
			case "SETINFO":
				if len(args) >= 4 {
					switch strings.ToUpper(args[2]) {
					case "LIB-NAME":
						s.client["driver"] = args[3]
					case "LIB-VER":
						s.client["driver_version"] = args[3]
					}
				}
			}
		}
		return s.reply(redisErrNoAuth)
	case "QUIT":
		s.reply("+OK\r\n")
		return false
	}
	return s.reply(redisErrNoAuth)
}

// hello handles HELLO [protover [AUTH user pass] [SETNAME name]].
func (s *redisSession) hello(args []string) bool {
	if len(args) >= 2 {
		v, err := strconv.Atoi(args[1])
		if err != nil {
			return s.reply("-ERR Protocol version is not an integer or out of range\r\n")
		}
		if v < 2 || v > 3 {
			return s.reply("-NOPROTO unsupported protocol version\r\n")
		}
	}
	user, pass, auth := "", "", false
	for i := 2; i < len(args); i++ {
		left := len(args) - i - 1
		switch opt := strings.ToUpper(args[i]); {
		case opt == "AUTH" && left >= 2:
			user, pass, auth = args[i+1], args[i+2], true
			i += 2
		case opt == "SETNAME" && left >= 1:
			s.client["client_name"] = args[i+1]
			i++
		default:
			return s.reply(fmt.Sprintf("-ERR Syntax error in HELLO option '%s'\r\n", redisClean(args[i])))
		}
	}
	if auth {
		s.record(user, pass)
		return s.reply(redisErrWrongPass)
	}
	return s.reply(redisErrHelloAuth)
}

// record logs a captured credential along with any client metadata seen.
func (s *redisSession) record(user, pass string) {
	rec := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", s.conf.BindHost, s.conf.BindPort),
		"username": user,
		"password": pass,
	}
	for k, v := range s.client {
		rec[k] = v
	}
	s.conf.RecordWriter.Record("credential", "redis", s.conn.RemoteAddr().String(), rec)
}

// reply writes one response and reports whether the write succeeded.
func (s *redisSession) reply(r string) bool {
	_, err := io.WriteString(s.conn, r)
	return err == nil
}

// redisClean strips CR and LF so client text cannot break the reply framing.
func redisClean(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// redisReadCommand reads a RESP multibulk command or an inline command.
func redisReadCommand(br *bufio.Reader) ([]string, error) {
	line, err := redisReadLine(br)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 || line[0] != '*' {
		f := strings.Fields(string(line))
		if len(f) > redisMaxArgs {
			f = f[:redisMaxArgs]
		}
		return f, nil
	}
	n, err := strconv.Atoi(string(line[1:]))
	if err != nil || n > redisMaxArgs {
		return nil, fmt.Errorf("%w: invalid multibulk length", errRedisProto)
	}
	args := make([]string, 0, max(n, 0))
	for range n {
		hdr, err := redisReadLine(br)
		if err != nil {
			return nil, err
		}
		if len(hdr) == 0 || hdr[0] != '$' {
			return nil, fmt.Errorf("%w: expected '$', got '%c'", errRedisProto, redisFirstByte(hdr))
		}
		size, err := strconv.Atoi(string(hdr[1:]))
		if err != nil || size < 0 || size > redisMaxBulk {
			return nil, fmt.Errorf("%w: invalid bulk length", errRedisProto)
		}
		b := make([]byte, size+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		args = append(args, string(b[:size]))
	}
	return args, nil
}

// redisFirstByte returns the first printable byte of b, or a space.
func redisFirstByte(b []byte) byte {
	if len(b) == 0 || b[0] < 0x20 || b[0] > 0x7e {
		return ' '
	}
	return b[0]
}

// redisReadLine reads one CRLF or LF terminated line of at most redisMaxLine bytes.
func redisReadLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > redisMaxLine {
			return nil, fmt.Errorf("%w: too big inline request", errRedisProto)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 && errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}
