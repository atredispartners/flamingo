package flamingo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// socksMaxString caps a NUL-terminated SOCKS4 user id or host name.
const socksMaxString = 255

// socksTimeout is the idle deadline applied to each client connection.
const socksTimeout = 30 * time.Second

// SOCKS method and reply codes.
const (
	socksMethodNone     = 0x00
	socksMethodUserPass = 0x02
	socksMethodRefused  = 0xff

	socksRep5NotAllowed  = 0x02
	socksRep5BadCommand  = 0x07
	socksRep5BadAddrType = 0x08
	socksRep4Rejected    = 0x5b
)

// ConfSOCKS holds the configuration for a SOCKS capture server.
type ConfSOCKS struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfSOCKS creates a default configuration for the SOCKS capture server.
func NewConfSOCKS() *ConfSOCKS {
	return &ConfSOCKS{
		BindPort: 1080,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfSOCKS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfSOCKS) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnSOCKS creates a new SOCKS capture server.
func SpawnSOCKS(c *ConfSOCKS) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("socks is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go socksStart(c)
	return nil
}

func socksStart(c *ConfSOCKS) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go socksHandleConnection(c, conn)
	}
}

// record logs a captured credential for the given protocol version.
func (c *ConfSOCKS) record(conn net.Conn, version string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"version": version,
	}
	for k, v := range fields {
		rec[k] = v
	}
	c.RecordWriter.Record("credential", "socks", conn.RemoteAddr().String(), rec)
}

// socksReader reads protocol fields and remembers the first error.
type socksReader struct {
	br  *bufio.Reader
	err error
}

func (r *socksReader) byte() byte {
	if r.err != nil {
		return 0
	}
	b, err := r.br.ReadByte()
	r.err = err
	return b
}

func (r *socksReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	b := make([]byte, n)
	_, r.err = io.ReadFull(r.br, b)
	return b
}

func (r *socksReader) u16() uint16 {
	b := r.bytes(2)
	if r.err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// cstring reads a NUL-terminated string of at most socksMaxString bytes.
func (r *socksReader) cstring() ([]byte, bool) {
	var s []byte
	for r.err == nil {
		b := r.byte()
		if r.err != nil {
			return s, false
		}
		if b == 0 {
			return s, true
		}
		if len(s) >= socksMaxString {
			return s, false
		}
		s = append(s, b)
	}
	return s, false
}

// socksHandleConnection dispatches on the version byte and refuses every
// request after capturing whatever credentials and target it carries.
func socksHandleConnection(c *ConfSOCKS, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(socksTimeout))

	r := &socksReader{br: bufio.NewReader(conn)}
	switch r.byte() {
	case 4:
		socks4(c, conn, r)
	case 5:
		socks5(c, conn, r)
	}
}

// socks4 parses a SOCKS4 or SOCKS4a request, records the USERID and target,
// and rejects it.
func socks4(c *ConfSOCKS, conn net.Conn, r *socksReader) {
	r.byte() // command
	port := r.u16()
	ip := r.bytes(4)
	if r.err != nil {
		return
	}
	user, ok := r.cstring()
	if !ok {
		return
	}
	version := "4"
	var host string
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		version = "4a"
		h, ok := r.cstring()
		if !ok {
			return
		}
		host = string(h)
	} else {
		host = netip.AddrFrom4([4]byte(ip)).String()
	}
	c.record(conn, version, map[string]string{
		"username": string(user),
		"target":   socksTarget(host, port),
	})
	conn.Write([]byte{0, socksRep4Rejected, 0, 0, 0, 0, 0, 0})
}

// socks5 negotiates a method, then either fails a username/password login
// or reads the request to learn the target and refuses it.
func socks5(c *ConfSOCKS, conn net.Conn, r *socksReader) {
	n := r.byte()
	methods := r.bytes(int(n))
	if r.err != nil {
		return
	}
	switch {
	case slices.Contains(methods, socksMethodUserPass):
		if _, err := conn.Write([]byte{5, socksMethodUserPass}); err != nil {
			return
		}
		socks5Login(c, conn, r)
	case slices.Contains(methods, socksMethodNone):
		if _, err := conn.Write([]byte{5, socksMethodNone}); err != nil {
			return
		}
		socks5Request(conn, r)
	default:
		conn.Write([]byte{5, socksMethodRefused})
	}
}

// socks5Login reads an RFC 1929 username/password subnegotiation, records
// it, and reports failure.
func socks5Login(c *ConfSOCKS, conn net.Conn, r *socksReader) {
	r.byte() // subnegotiation version
	user := r.bytes(int(r.byte()))
	pass := r.bytes(int(r.byte()))
	if r.err != nil {
		return
	}
	c.record(conn, "5", map[string]string{
		"username": string(user),
		"password": string(pass),
	})
	conn.Write([]byte{1, 1})
}

// socks5Request reads a SOCKS5 request on an unauthenticated session and
// refuses it. No credential is involved, so the target is only logged.
func socks5Request(conn net.Conn, r *socksReader) {
	v := r.byte()
	cmd := r.byte()
	r.byte() // reserved
	atyp := r.byte()
	if r.err != nil || v != 5 {
		return
	}
	var host string
	switch atyp {
	case 1:
		b := r.bytes(4)
		if r.err == nil {
			host = netip.AddrFrom4([4]byte(b)).String()
		}
	case 3:
		host = string(r.bytes(int(r.byte())))
	case 4:
		b := r.bytes(16)
		if r.err == nil {
			host = netip.AddrFrom16([16]byte(b)).String()
		}
	default:
		socksReply5(conn, socksRep5BadAddrType)
		return
	}
	port := r.u16()
	if r.err != nil {
		return
	}
	log.Debugf("socks5 request from %s for %s (command %d) without credentials", conn.RemoteAddr(), socksTarget(host, port), cmd)
	if cmd < 1 || cmd > 3 {
		socksReply5(conn, socksRep5BadCommand)
		return
	}
	socksReply5(conn, socksRep5NotAllowed)
}

// socksTarget formats a host and port as host:port.
func socksTarget(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// socksReply5 sends a SOCKS5 reply with an unspecified IPv4 bind address.
func socksReply5(conn net.Conn, rep byte) {
	conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}
