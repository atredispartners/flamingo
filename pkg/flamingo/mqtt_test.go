package flamingo

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// mqttTestServer spawns an MQTT collector on a free port and returns the
// address plus a channel that receives captured records.
func mqttTestServer(t *testing.T) (string, chan map[string]string, *ConfMQTT) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		select {
		case got <- rec:
		default:
		}
		return nil
	})

	conf := NewConfMQTT()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnMQTT(conf); err != nil {
		t.Fatalf("SpawnMQTT: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return conf.listener.Addr().String(), got, conf
}

func mqttWaitRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no record written")
		return nil
	}
}

// mqttStr encodes a two-byte-length-prefixed MQTT string.
func mqttStr(s string) []byte {
	b := make([]byte, 2, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	return append(b, s...)
}

// mqttVarint encodes an MQTT variable byte integer.
func mqttVarint(n int) []byte {
	var out []byte
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

// mqttPacket wraps a body in a fixed header of the given type.
func mqttPacket(typ byte, body []byte) []byte {
	out := []byte{typ << 4}
	out = append(out, mqttVarint(len(body))...)
	return append(out, body...)
}

// mqttConnectPacket builds a CONNECT for the given protocol level.
func mqttConnectPacket(protocol string, level byte, clientID, user, pass string, will bool) []byte {
	flags := byte(mqttFlagCleanSession)
	if user != "" {
		flags |= mqttFlagUsername
	}
	if pass != "" {
		flags |= mqttFlagPassword
	}
	if will {
		flags |= mqttFlagWill
	}

	body := mqttStr(protocol)
	body = append(body, level, flags)
	body = append(body, 0x00, 0x3c) // keep alive 60
	if level >= mqttLevel5 {
		body = append(body, 0x00) // empty property block
	}
	body = append(body, mqttStr(clientID)...)
	if will {
		if level >= mqttLevel5 {
			body = append(body, 0x00) // empty will properties
		}
		body = append(body, mqttStr("devices/offline")...)
		body = append(body, mqttStr("bye")...)
	}
	if user != "" {
		body = append(body, mqttStr(user)...)
	}
	if pass != "" {
		body = append(body, mqttStr(pass)...)
	}
	return mqttPacket(mqttCONNECT, body)
}

// mqttSend writes a packet and reads whatever comes back before the server
// closes the connection.
func mqttSend(t *testing.T, addr string, pkt []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %s", err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		return reply
	}
	return reply
}

// TestMQTTConnectCapture checks a CONNECT at each protocol level, including
// the 3.1 MQIsdp name and the 5.0 property blocks, and the shape of the
// CONNACK each gets back.
func TestMQTTConnectCapture(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		level    byte
		version  string
		connack  []byte
	}{
		{"3.1", "MQIsdp", mqttLevel31, "3.1",
			[]byte{mqttCONNACK << 4, 0x02, 0x00, mqttReturnBadCredentials}},
		{"3.1.1", "MQTT", mqttLevel311, "3.1.1",
			[]byte{mqttCONNACK << 4, 0x02, 0x00, mqttReturnBadCredentials}},
		{"5.0", "MQTT", mqttLevel5, "5.0",
			[]byte{mqttCONNACK << 4, 0x03, 0x00, mqttReasonBadCredentials, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got, _ := mqttTestServer(t)
			pkt := mqttConnectPacket(tc.protocol, tc.level,
				"sensor-07", "iotadmin", "Tr0ub4dor&3", true)

			reply := mqttSend(t, addr, pkt)
			if !bytes.Equal(reply, tc.connack) {
				t.Errorf("CONNACK = %x, want %x", reply, tc.connack)
			}

			rec := mqttWaitRecord(t, got)
			if rec["_type"] != "credential" || rec["_proto"] != "mqtt" {
				t.Fatalf("record = %v", rec)
			}
			if rec["username"] != "iotadmin" {
				t.Errorf("username = %q, want iotadmin", rec["username"])
			}
			if rec["password"] != "Tr0ub4dor&3" {
				t.Errorf("password = %q, want Tr0ub4dor&3", rec["password"])
			}
			if rec["client_id"] != "sensor-07" {
				t.Errorf("client_id = %q, want sensor-07", rec["client_id"])
			}
			if rec["version"] != tc.version {
				t.Errorf("version = %q, want %q", rec["version"], tc.version)
			}
			if rec["protocol"] != tc.protocol {
				t.Errorf("protocol = %q, want %q", rec["protocol"], tc.protocol)
			}
			if rec["will_topic"] != "devices/offline" {
				t.Errorf("will_topic = %q", rec["will_topic"])
			}
			if rec["keepalive"] != "60" {
				t.Errorf("keepalive = %q, want 60", rec["keepalive"])
			}
		})
	}
}

// TestMQTTConnectNoCredential checks that an anonymous CONNECT is logged as an
// observation rather than as a credential, and is still refused.
func TestMQTTConnectNoCredential(t *testing.T) {
	addr, got, _ := mqttTestServer(t)

	reply := mqttSend(t, addr, mqttConnectPacket("MQTT", mqttLevel311, "anon-client", "", "", false))
	if len(reply) == 0 {
		t.Fatal("no CONNACK")
	}

	rec := mqttWaitRecord(t, got)
	if rec["_type"] != "access" {
		t.Errorf("_type = %q, want access", rec["_type"])
	}
	if rec["client_id"] != "anon-client" {
		t.Errorf("client_id = %q", rec["client_id"])
	}
	if rec["username"] != "" || rec["password"] != "" {
		t.Errorf("username/password = %q/%q, want empty", rec["username"], rec["password"])
	}
}

// TestMQTTPasswordWithoutUsername covers the client that sets only the
// password flag, which the spec discourages and brokers see anyway.
func TestMQTTPasswordWithoutUsername(t *testing.T) {
	addr, got, _ := mqttTestServer(t)

	body := mqttStr("MQTT")
	body = append(body, mqttLevel311, mqttFlagPassword|mqttFlagCleanSession)
	body = append(body, 0x00, 0x0a)
	body = append(body, mqttStr("c1")...)
	body = append(body, mqttStr("only-a-password")...)
	mqttSend(t, addr, mqttPacket(mqttCONNECT, body))

	rec := mqttWaitRecord(t, got)
	if rec["_type"] != "credential" {
		t.Fatalf("_type = %q, want credential", rec["_type"])
	}
	if rec["password"] != "only-a-password" {
		t.Errorf("password = %q", rec["password"])
	}
}

// TestMQTTMalformed feeds truncated, oversized and nonsense packets to the
// listener and requires that none of them panics, hangs, or yields a
// credential, and that the listener keeps working afterwards.
func TestMQTTMalformed(t *testing.T) {
	addr, got, _ := mqttTestServer(t)

	good := mqttConnectPacket("MQTT", mqttLevel311, "c", "u", "p", false)

	cases := [][]byte{
		{},
		{0x10},
		{0x10, 0x00},                         // CONNECT with an empty body
		{0x10, 0xff, 0xff, 0xff, 0xff, 0xff}, // malformed remaining length
		{0x10, 0xff, 0xff, 0xff, 0x7f},       // 268 MB, refused on size
		{0xe0, 0x00},                         // DISCONNECT as the first packet
		{0x30, 0x02, 0x00, 0x00},             // PUBLISH as the first packet
		// A CONNECT whose string lengths lie about what follows.
		mqttPacket(mqttCONNECT, append(mqttStr("MQTT"),
			mqttLevel311, mqttFlagUsername|mqttFlagPassword, 0x00, 0x0a,
			0xff, 0xff)),
		// A protocol name we do not recognise.
		mqttPacket(mqttCONNECT, append(mqttStr("HTTP/1.1"), mqttLevel311, 0x00, 0x00, 0x00)),
		// MQTT 5.0 with a property length past the end of the packet.
		mqttPacket(mqttCONNECT, append(mqttStr("MQTT"),
			mqttLevel5, mqttFlagCleanSession, 0x00, 0x0a, 0x7f)),
	}
	for i := 1; i < len(good); i++ {
		cases = append(cases, good[:i])
	}

	for _, pkt := range cases {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial: %s", err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(pkt)
		conn.Close()
	}

	// Nothing above may be recorded as a credential.
	drained := time.After(500 * time.Millisecond)
	for done := false; !done; {
		select {
		case rec := <-got:
			if rec["_type"] == "credential" {
				t.Fatalf("malformed packet produced a credential: %v", rec)
			}
		case <-drained:
			done = true
		}
	}

	// The listener is still alive.
	reply := mqttSend(t, addr, good)
	if len(reply) == 0 {
		t.Fatal("the listener stopped answering after malformed input")
	}
	rec := mqttWaitRecord(t, got)
	if rec["username"] != "u" {
		t.Fatalf("record = %v", rec)
	}
}

// TestMQTTParseConnectDirect exercises the parser on its own, where a failure
// is easier to read than through a socket.
func TestMQTTParseConnectDirect(t *testing.T) {
	// A 5.0 CONNECT with a non-empty property block, which must be stepped
	// over without disturbing the payload that follows.
	props := []byte{0x11, 0x00, 0x00, 0x0e, 0x10} // session expiry interval
	body := mqttStr("MQTT")
	body = append(body, mqttLevel5, mqttFlagUsername|mqttFlagPassword|mqttFlagCleanSession)
	body = append(body, 0x00, 0x1e)
	body = append(body, mqttVarint(len(props))...)
	body = append(body, props...)
	body = append(body, mqttStr("client-5")...)
	body = append(body, mqttStr("mqtt-user")...)
	body = append(body, mqttStr("mqtt-pass")...)

	m, err := mqttParseConnect(body)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if m.Username != "mqtt-user" || m.Password != "mqtt-pass" {
		t.Errorf("username/password = %q/%q", m.Username, m.Password)
	}
	if m.ClientID != "client-5" {
		t.Errorf("client id = %q", m.ClientID)
	}
	if m.KeepAlive != 30 {
		t.Errorf("keepalive = %d, want 30", m.KeepAlive)
	}
	if !m.CleanSession {
		t.Error("clean session flag was not decoded")
	}
}
