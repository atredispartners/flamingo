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
	"math"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// AMQP 0-9-1 framing constants and parser limits.
const (
	amqpFrameMethod = 1
	amqpFrameEnd    = 0xce
	amqpMaxFrame    = 32 << 10
	amqpMaxDepth    = 4
	amqpMaxFields   = 128
	amqpClassConn   = 10
	amqpMethStart   = 10
	amqpMethStartOk = 11
	amqpMethClose   = 50
)

// amqpTimeout is the idle deadline applied to each client connection.
const amqpTimeout = 30 * time.Second

// amqpHeader is the protocol header for AMQP 0-9-1.
var amqpHeader = []byte("AMQP\x00\x00\x09\x01")

// errAMQPFormat reports a malformed frame or field.
var errAMQPFormat = errors.New("amqp: malformed frame")

// ConfAMQP describes the options for an AMQP capture service. The TLS flag
// selects implicit TLS (AMQPS).
type ConfAMQP struct {
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

// NewConfAMQP creates a default configuration for the AMQP capture server.
func NewConfAMQP() *ConfAMQP {
	return &ConfAMQP{
		BindPort: 5672,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfAMQP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfAMQP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnAMQP starts a logging AMQP or AMQPS server.
func SpawnAMQP(c *ConfAMQP) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)

	if !c.TLS {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s (%s)", addr, err)
		}
		c.listener = listener
		log.Debugf("amqp is listening on %s", addr)
		go amqpStart(c)
		return nil
	}

	tlsConfig, err := c.tlsConfig()
	if err != nil {
		return fmt.Errorf("failed to load tls cert for amqps on %s (%s)", addr, err)
	}
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s (%s)", addr, err)
	}
	c.listener = listener
	log.Debugf("amqps is listening on %s", addr)
	go amqpStart(c)
	return nil
}

// tlsConfig builds a server TLS configuration from the configured key pair.
func (c *ConfAMQP) tlsConfig() (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName:   c.TLSName,
		Certificates: []tls.Certificate{kp},
	}, nil
}

func amqpStart(c *ConfAMQP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go amqpHandleConnection(c, conn)
	}
}

// pname returns the protocol name used in credential records.
func (c *ConfAMQP) pname() string {
	if c.TLS {
		return "amqps"
	}
	return "amqp"
}

// record logs a captured credential with the given method and fields.
func (c *ConfAMQP) record(conn net.Conn, method string, fields map[string]string) {
	rec := map[string]string{
		"_server": fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":  method,
	}
	maps.Copy(rec, fields)
	c.RecordWriter.Record("credential", c.pname(), conn.RemoteAddr().String(), rec)
}

// amqpHandleConnection runs the connection handshake as a RabbitMQ-like
// broker: it checks the protocol header, sends Connection.Start, records the
// credentials from Connection.Start-Ok and refuses them with Connection.Close.
func amqpHandleConnection(c *ConfAMQP, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(amqpTimeout))

	var h [8]byte
	n, err := io.ReadFull(conn, h[:])
	if err != nil || !bytes.Equal(h[:], amqpHeader) {
		// Any other header is answered with the supported version.
		if n > 0 {
			conn.Write(amqpHeader)
		}
		return
	}
	if _, err := conn.Write(amqpStartFrame()); err != nil {
		return
	}

	typ, ch, payload, err := amqpReadFrame(conn)
	if err != nil {
		return
	}
	if typ != amqpFrameMethod || ch != 0 || len(payload) < 4 ||
		binary.BigEndian.Uint32(payload) != amqpClassConn<<16|amqpMethStartOk {
		conn.Write(amqpCloseFrame(503, "COMMAND_INVALID - expected 'connection.start_ok'"))
		return
	}

	mech := amqpStartOk(c, conn, payload[4:])
	conn.Write(amqpCloseFrame(403, "ACCESS_REFUSED - Login was refused using authentication mechanism "+
		mech+". For details see the broker logfile."))

	// Give the client a moment to answer with Connection.Close-Ok.
	conn.SetDeadline(time.Now().Add(time.Second))
	amqpReadFrame(conn)
}

// amqpStartOk parses the Connection.Start-Ok arguments, records the client
// properties and credentials, and returns the mechanism name.
func amqpStartOk(c *ConfAMQP, conn net.Conn, b []byte) string {
	p := &amqpParser{b: b}
	fields := map[string]string{}

	props, err := p.table(0)
	if err != nil {
		return "PLAIN"
	}
	for _, k := range []string{"product", "version", "platform", "connection_name"} {
		if v, ok := props[k].(string); ok && v != "" {
			fields[k] = v
		}
	}

	mech, err := p.shortstr()
	if err != nil {
		return "PLAIN"
	}
	mech = strings.ToUpper(mech)
	resp, err := p.longstr()
	if err != nil {
		return mech
	}

	switch mech {
	case "PLAIN":
		// The response is "[authzid]\x00authcid\x00password".
		parts := strings.SplitN(resp, "\x00", 3)
		if len(parts) == 3 {
			fields["username"] = parts[1]
			fields["password"] = parts[2]
			if parts[0] != "" {
				fields["authzid"] = parts[0]
			}
			c.record(conn, mech, fields)
			return mech
		}
	case "AMQPLAIN":
		// The response is a field table without its length prefix; some
		// clients include the prefix, so accept either form.
		t, err := (&amqpParser{b: []byte(resp)}).fields(len(resp), 0)
		if err != nil {
			t, err = (&amqpParser{b: []byte(resp)}).table(0)
		}
		if err == nil {
			u, _ := t["LOGIN"].(string)
			pw, _ := t["PASSWORD"].(string)
			if u != "" || pw != "" {
				fields["username"] = u
				fields["password"] = pw
				c.record(conn, mech, fields)
				return mech
			}
		}
	}

	// Unknown mechanisms or unparsed responses are kept verbatim.
	fields["response"] = amqpPrintable(resp)
	c.record(conn, mech, fields)
	return mech
}

// amqpReadFrame reads one frame and returns its type, channel and payload.
func amqpReadFrame(r io.Reader) (typ byte, ch uint16, payload []byte, err error) {
	var h [7]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	typ, ch = h[0], binary.BigEndian.Uint16(h[1:3])
	size := binary.BigEndian.Uint32(h[3:7])
	if size > amqpMaxFrame {
		return typ, ch, nil, errAMQPFormat
	}
	payload = make([]byte, size+1)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	if payload[size] != amqpFrameEnd {
		return typ, ch, nil, errAMQPFormat
	}
	return typ, ch, payload[:size], nil
}

// amqpStartFrame builds Connection.Start with RabbitMQ-like server
// properties offering the PLAIN and AMQPLAIN mechanisms.
func amqpStartFrame() []byte {
	var w amqpEnc
	w.u16(amqpClassConn)
	w.u16(amqpMethStart)
	w.b = append(w.b, 0, 9)
	w.table([]amqpField{
		{"capabilities", []amqpField{
			{"publisher_confirms", true},
			{"exchange_exchange_bindings", true},
			{"basic.nack", true},
			{"consumer_cancel_notify", true},
			{"connection.blocked", true},
			{"consumer_priorities", true},
			{"authentication_failure_close", true},
			{"per_consumer_qos", true},
			{"direct_reply_to", true},
		}},
		{"cluster_name", "rabbit@mq01"},
		{"copyright", "Copyright (c) 2007-2024 Broadcom Inc and/or its subsidiaries"},
		{"information", "Licensed under the MPL 2.0. Website: https://rabbitmq.com"},
		{"platform", "Erlang/OTP 26.2.5.6"},
		{"product", "RabbitMQ"},
		{"version", "3.13.7"},
	})
	w.longstr("PLAIN AMQPLAIN")
	w.longstr("en_US")
	return amqpFrame(w.b)
}

// amqpCloseFrame builds Connection.Close with a reply code and text.
func amqpCloseFrame(code uint16, text string) []byte {
	var w amqpEnc
	w.u16(amqpClassConn)
	w.u16(amqpMethClose)
	w.u16(code)
	w.shortstr(text)
	w.u16(0)
	w.u16(0)
	return amqpFrame(w.b)
}

// amqpFrame wraps a method payload in a channel 0 frame.
func amqpFrame(payload []byte) []byte {
	out := []byte{amqpFrameMethod, 0, 0}
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	return append(out, amqpFrameEnd)
}

// amqpField is one entry of a field table; val is a bool, string or nested
// []amqpField.
type amqpField struct {
	name string
	val  any
}

// amqpEnc builds AMQP method arguments.
type amqpEnc struct{ b []byte }

func (w *amqpEnc) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }

func (w *amqpEnc) shortstr(s string) {
	if len(s) > 255 {
		s = s[:255]
	}
	w.b = append(w.b, byte(len(s)))
	w.b = append(w.b, s...)
}

func (w *amqpEnc) longstr(s string) {
	w.b = binary.BigEndian.AppendUint32(w.b, uint32(len(s)))
	w.b = append(w.b, s...)
}

func (w *amqpEnc) table(fs []amqpField) {
	var t amqpEnc
	for _, f := range fs {
		t.shortstr(f.name)
		switch v := f.val.(type) {
		case bool:
			t.b = append(t.b, 't')
			if v {
				t.b = append(t.b, 1)
			} else {
				t.b = append(t.b, 0)
			}
		case string:
			t.b = append(t.b, 'S')
			t.longstr(v)
		case []amqpField:
			t.b = append(t.b, 'F')
			t.table(v)
		}
	}
	w.b = binary.BigEndian.AppendUint32(w.b, uint32(len(t.b)))
	w.b = append(w.b, t.b...)
}

// amqpParser decodes AMQP 0-9-1 method arguments with bounds checks; every
// length is checked against the bytes remaining before anything is read.
type amqpParser struct {
	b []byte
}

func (p *amqpParser) take(n int) ([]byte, error) {
	if n < 0 || n > len(p.b) {
		return nil, errAMQPFormat
	}
	v := p.b[:n]
	p.b = p.b[n:]
	return v, nil
}

func (p *amqpParser) u8() (byte, error) {
	b, err := p.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *amqpParser) u32() (uint32, error) {
	b, err := p.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (p *amqpParser) shortstr() (string, error) {
	n, err := p.u8()
	if err != nil {
		return "", err
	}
	b, err := p.take(int(n))
	return string(b), err
}

func (p *amqpParser) longstr() (string, error) {
	n, err := p.u32()
	if err != nil || n > uint32(len(p.b)) {
		return "", errAMQPFormat
	}
	b, err := p.take(int(n))
	return string(b), err
}

// table decodes a length-prefixed field table.
func (p *amqpParser) table(depth int) (map[string]any, error) {
	n, err := p.u32()
	if err != nil || n > uint32(len(p.b)) {
		return nil, errAMQPFormat
	}
	return p.fields(int(n), depth)
}

// fields decodes n bytes of name/value pairs.
func (p *amqpParser) fields(n, depth int) (map[string]any, error) {
	body, err := p.take(n)
	if err != nil {
		return nil, err
	}
	q := &amqpParser{b: body}
	out := map[string]any{}
	for len(q.b) > 0 {
		if len(out) >= amqpMaxFields {
			return nil, errAMQPFormat
		}
		name, err := q.shortstr()
		if err != nil {
			return nil, err
		}
		v, err := q.value(depth)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// value decodes one typed field value.
func (p *amqpParser) value(depth int) (any, error) {
	if depth > amqpMaxDepth {
		return nil, errAMQPFormat
	}
	t, err := p.u8()
	if err != nil {
		return nil, err
	}
	switch t {
	case 't':
		b, err := p.take(1)
		if err != nil {
			return nil, err
		}
		return b[0] != 0, nil
	case 'b', 'B':
		b, err := p.take(1)
		if err != nil {
			return nil, err
		}
		return int64(b[0]), nil
	case 's', 'u':
		b, err := p.take(2)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint16(b)), nil
	case 'I', 'i':
		b, err := p.take(4)
		if err != nil {
			return nil, err
		}
		return int64(int32(binary.BigEndian.Uint32(b))), nil
	case 'l', 'L', 'T':
		b, err := p.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case 'f':
		b, err := p.take(4)
		if err != nil {
			return nil, err
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
	case 'd':
		b, err := p.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
	case 'D':
		if _, err := p.take(5); err != nil {
			return nil, err
		}
		return "decimal", nil
	case 'S', 'x':
		s, err := p.longstr()
		if err != nil {
			return nil, err
		}
		if t == 'x' {
			return hex.EncodeToString([]byte(s)), nil
		}
		return s, nil
	case 'F':
		return p.table(depth + 1)
	case 'A':
		n, err := p.u32()
		if err != nil || n > uint32(len(p.b)) {
			return nil, errAMQPFormat
		}
		body, _ := p.take(int(n))
		q := &amqpParser{b: body}
		var arr []any
		for len(q.b) > 0 && len(arr) < amqpMaxFields {
			v, err := q.value(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 'V':
		return nil, nil
	}
	return nil, errAMQPFormat
}

// amqpPrintable replaces control characters and invalid UTF-8 so a raw
// response can be stored as text.
func amqpPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}
