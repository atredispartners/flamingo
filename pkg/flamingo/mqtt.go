package flamingo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// MQTT control packet types, in the high nibble of the first byte.
const (
	mqttCONNECT = 1
	mqttCONNACK = 2
)

// MQTT protocol levels. 3 is the MQIsdp wire format of MQTT 3.1, 4 is MQTT
// 3.1.1, and 5 is MQTT 5.0, which adds property blocks to the variable header
// and the will payload.
const (
	mqttLevel31  = 3
	mqttLevel311 = 4
	mqttLevel5   = 5
)

// CONNECT flag bits (MQTT 3.1.1 section 3.1.2.3).
const (
	mqttFlagCleanSession = 0x02
	mqttFlagWill         = 0x04
	mqttFlagPassword     = 0x40
	mqttFlagUsername     = 0x80
)

// CONNACK refusal codes. The 3.1/3.1.1 return code and the 5.0 reason code are
// different numbering schemes for the same answer: the credential was wrong.
const (
	mqttReturnBadCredentials = 0x04
	mqttReasonBadCredentials = 0x86
)

// Session limits. A CONNECT is the first thing a client sends and is small;
// anything much larger than this is not a credential worth waiting for.
const (
	mqttMaxPacket = 64 * 1024
	mqttMaxVarint = 4
	mqttTimeout   = 30 * time.Second
)

// ConfMQTT holds the configuration for an MQTT broker capture server.
type ConfMQTT struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfMQTT creates a default configuration for the MQTT capture server.
func NewConfMQTT() *ConfMQTT {
	return &ConfMQTT{
		BindPort: 1883,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMQTT) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMQTT) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnMQTT starts a logging MQTT broker.
func SpawnMQTT(c *ConfMQTT) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("mqtt is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go mqttStart(c)
	return nil
}

func mqttStart(c *ConfMQTT) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go mqttHandleConnection(c, conn)
	}
}

// mqttHandleConnection reads one CONNECT, records whatever it carries, and
// refuses the connection with "bad user name or password" so the client
// retries — often with a different credential.
func mqttHandleConnection(c *ConfMQTT, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(mqttTimeout))

	typ, body, err := mqttReadPacket(conn)
	if err != nil {
		log.Debugf("mqtt read from %s: %s", conn.RemoteAddr(), err)
		return
	}
	if typ != mqttCONNECT {
		log.Debugf("mqtt unexpected packet type %d from %s", typ, conn.RemoteAddr())
		return
	}

	connect, err := mqttParseConnect(body)
	if err != nil {
		log.Debugf("mqtt connect from %s: %s", conn.RemoteAddr(), err)
		return
	}

	rtype := "access"
	if connect.HasUsername || connect.HasPassword {
		rtype = "credential"
	}
	fields := connect.fields()
	fields["_server"] = fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	c.RecordWriter.Record(rtype, "mqtt", conn.RemoteAddr().String(), fields)

	conn.Write(mqttConnackRefused(connect.Level))
}

// mqttReadPacket reads one control packet and returns its type and body. The
// remaining length is a variable byte integer of up to four bytes, each
// carrying seven bits with the high bit marking a continuation.
func mqttReadPacket(conn net.Conn) (byte, []byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return 0, nil, err
	}

	length := 0
	multiplier := 1
	for i := 0; ; i++ {
		if i >= mqttMaxVarint {
			return first[0] >> 4, nil, errors.New("remaining length is malformed")
		}
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return first[0] >> 4, nil, err
		}
		length += int(b[0]&0x7f) * multiplier
		if b[0]&0x80 == 0 {
			break
		}
		multiplier *= 128
	}
	if length < 0 || length > mqttMaxPacket {
		return first[0] >> 4, nil, fmt.Errorf("packet of %d bytes is too large", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return first[0] >> 4, nil, err
	}
	return first[0] >> 4, body, nil
}

// mqttConnect holds the fields decoded from a CONNECT packet.
type mqttConnect struct {
	Protocol     string
	Level        byte
	Flags        byte
	KeepAlive    uint16
	ClientID     string
	WillTopic    string
	Username     string
	Password     string
	HasUsername  bool
	HasPassword  bool
	CleanSession bool
}

// fields converts the decoded CONNECT into a record.
func (m *mqttConnect) fields() map[string]string {
	rec := map[string]string{
		"username":       m.Username,
		"password":       m.Password,
		"client_id":      m.ClientID,
		"protocol":       m.Protocol,
		"protocol_level": fmt.Sprintf("%d", m.Level),
		"version":        mqttVersionName(m.Protocol, m.Level),
		"keepalive":      fmt.Sprintf("%d", m.KeepAlive),
		"clean_session":  fmt.Sprintf("%t", m.CleanSession),
		"method":         "connect",
	}
	if m.WillTopic != "" {
		rec["will_topic"] = m.WillTopic
	}
	return rec
}

// mqttVersionName names the protocol version a level byte stands for.
func mqttVersionName(protocol string, level byte) string {
	switch level {
	case mqttLevel31:
		return "3.1"
	case mqttLevel311:
		return "3.1.1"
	case mqttLevel5:
		return "5.0"
	}
	return fmt.Sprintf("unknown (%s level %d)", protocol, level)
}

// mqttParseConnect decodes a CONNECT variable header and payload. Every
// string is length-prefixed, and every length is checked against what is left
// of the packet, so a truncated or lying packet is an error rather than a
// panic.
func mqttParseConnect(p []byte) (*mqttConnect, error) {
	r := &mqttReader{buf: p}

	protocol, err := r.str()
	if err != nil {
		return nil, fmt.Errorf("protocol name: %w", err)
	}
	// MQTT 3.1 calls itself MQIsdp, every later version calls itself MQTT.
	if protocol != "MQTT" && protocol != "MQIsdp" {
		return nil, fmt.Errorf("unknown protocol name %q", protocol)
	}

	level, err := r.byteAt()
	if err != nil {
		return nil, fmt.Errorf("protocol level: %w", err)
	}
	flags, err := r.byteAt()
	if err != nil {
		return nil, fmt.Errorf("connect flags: %w", err)
	}
	keepAlive, err := r.uint16()
	if err != nil {
		return nil, fmt.Errorf("keep alive: %w", err)
	}

	m := &mqttConnect{
		Protocol:     protocol,
		Level:        level,
		Flags:        flags,
		KeepAlive:    keepAlive,
		HasUsername:  flags&mqttFlagUsername != 0,
		HasPassword:  flags&mqttFlagPassword != 0,
		CleanSession: flags&mqttFlagCleanSession != 0,
	}

	// MQTT 5.0 inserts a property block before the payload.
	if level >= mqttLevel5 {
		if err := r.skipProperties(); err != nil {
			return nil, fmt.Errorf("connect properties: %w", err)
		}
	}

	if m.ClientID, err = r.str(); err != nil {
		return nil, fmt.Errorf("client id: %w", err)
	}

	if flags&mqttFlagWill != 0 {
		if level >= mqttLevel5 {
			if err := r.skipProperties(); err != nil {
				return nil, fmt.Errorf("will properties: %w", err)
			}
		}
		if m.WillTopic, err = r.str(); err != nil {
			return nil, fmt.Errorf("will topic: %w", err)
		}
		if _, err := r.str(); err != nil { // will payload
			return nil, fmt.Errorf("will payload: %w", err)
		}
	}

	// A 3.1.1 client may set the username flag and send nothing, and some
	// clients send a password with no username. Take whatever is there.
	if m.HasUsername {
		if m.Username, err = r.str(); err != nil {
			return nil, fmt.Errorf("username: %w", err)
		}
	}
	if m.HasPassword {
		// The password is binary data, not UTF-8, but it is a passphrase
		// in every case worth capturing.
		if m.Password, err = r.str(); err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
	}
	return m, nil
}

// mqttReader walks a CONNECT packet, refusing to read past its end.
type mqttReader struct {
	buf []byte
	at  int
}

func (r *mqttReader) left() int { return len(r.buf) - r.at }

func (r *mqttReader) byteAt() (byte, error) {
	if r.left() < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.buf[r.at]
	r.at++
	return b, nil
}

func (r *mqttReader) uint16() (uint16, error) {
	if r.left() < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint16(r.buf[r.at:])
	r.at += 2
	return v, nil
}

// str reads a two-byte-length-prefixed field.
func (r *mqttReader) str() (string, error) {
	n, err := r.uint16()
	if err != nil {
		return "", err
	}
	if int(n) > r.left() {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.buf[r.at : r.at+int(n)])
	r.at += int(n)
	return s, nil
}

// varint reads an MQTT variable byte integer.
func (r *mqttReader) varint() (int, error) {
	value := 0
	multiplier := 1
	for i := 0; ; i++ {
		if i >= mqttMaxVarint {
			return 0, errors.New("variable byte integer is malformed")
		}
		b, err := r.byteAt()
		if err != nil {
			return 0, err
		}
		value += int(b&0x7f) * multiplier
		if b&0x80 == 0 {
			return value, nil
		}
		multiplier *= 128
	}
}

// skipProperties steps over an MQTT 5.0 property block, whose contents are of
// no interest here.
func (r *mqttReader) skipProperties() error {
	n, err := r.varint()
	if err != nil {
		return err
	}
	if n < 0 || n > r.left() {
		return io.ErrUnexpectedEOF
	}
	r.at += n
	return nil
}

// mqttConnackRefused builds the CONNACK that refuses a connection for a bad
// credential. MQTT 5.0 replaced the one-byte return code with a reason code
// and a property block, so the packet differs by protocol level.
func mqttConnackRefused(level byte) []byte {
	if level >= mqttLevel5 {
		return []byte{mqttCONNACK << 4, 0x03, 0x00, mqttReasonBadCredentials, 0x00}
	}
	return []byte{mqttCONNACK << 4, 0x02, 0x00, mqttReturnBadCredentials}
}
