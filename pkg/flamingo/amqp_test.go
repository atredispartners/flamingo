package flamingo

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// amqpTestServer spawns an AMQP collector on a free port and returns the
// address plus a channel that receives captured credential records.
func amqpTestServer(t *testing.T) (string, chan map[string]string, *ConfAMQP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfAMQP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnAMQP(conf); err != nil {
		t.Fatalf("SpawnAMQP failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

// amqpDial connects, sends the protocol header and consumes Connection.Start.
func amqpDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(amqpHeader)

	typ, ch, payload, err := amqpReadFrame(conn)
	if err != nil {
		t.Fatalf("read Connection.Start: %s", err)
	}
	if typ != amqpFrameMethod || ch != 0 || len(payload) < 4 ||
		binary.BigEndian.Uint32(payload) != amqpClassConn<<16|amqpMethStart {
		t.Fatalf("unexpected first frame type=%d ch=%d payload=%x", typ, ch, payload)
	}
	p := &amqpParser{b: payload[4:]}
	p.take(2) // version-major, version-minor
	props, err := p.table(0)
	if err != nil {
		t.Fatalf("server properties: %s", err)
	}
	if props["product"] != "RabbitMQ" {
		t.Errorf("server product = %v, want RabbitMQ", props["product"])
	}
	mechs, _ := p.longstr()
	if mechs != "PLAIN AMQPLAIN" {
		t.Errorf("mechanisms = %q, want PLAIN AMQPLAIN", mechs)
	}
	return conn
}

// amqpStartOkFrame builds Connection.Start-Ok with the given client
// properties, mechanism and response.
func amqpStartOkFrame(props []amqpField, mech, resp string) []byte {
	var w amqpEnc
	w.u16(amqpClassConn)
	w.u16(amqpMethStartOk)
	w.table(props)
	w.shortstr(mech)
	w.longstr(resp)
	w.shortstr("en_US")
	return amqpFrame(w.b)
}

// amqpExpectClose reads Connection.Close, checks the reply code and answers
// with Connection.Close-Ok.
func amqpExpectClose(t *testing.T, conn net.Conn, code uint16) {
	t.Helper()
	typ, _, payload, err := amqpReadFrame(conn)
	if err != nil {
		t.Fatalf("read Connection.Close: %s", err)
	}
	if typ != amqpFrameMethod || len(payload) < 6 ||
		binary.BigEndian.Uint32(payload) != amqpClassConn<<16|amqpMethClose {
		t.Fatalf("unexpected frame type=%d payload=%x", typ, payload)
	}
	if got := binary.BigEndian.Uint16(payload[4:6]); got != code {
		t.Errorf("close code = %d, want %d", got, code)
	}
	var w amqpEnc
	w.u16(amqpClassConn)
	w.u16(51)
	conn.Write(amqpFrame(w.b))
}

func amqpWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// TestAMQPPlain verifies a PLAIN login with client properties is captured
// and refused with ACCESS_REFUSED.
func TestAMQPPlain(t *testing.T) {
	addr, got, conf := amqpTestServer(t)
	defer conf.Shutdown()

	conn := amqpDial(t, addr)
	defer conn.Close()

	props := []amqpField{
		{"product", "AMQP 0.9.1 Client"},
		{"version", "1.10.0"},
		{"platform", "golang"},
		{"connection_name", "worker-1"},
		{"capabilities", []amqpField{{"connection.blocked", true}}},
	}
	conn.Write(amqpStartOkFrame(props, "PLAIN", "\x00svc\x00s3cr3t"))
	amqpExpectClose(t, conn, 403)

	rec := amqpWaitCred(t, got)
	if rec["_proto"] != "amqp" {
		t.Errorf("_proto = %q, want amqp", rec["_proto"])
	}
	if rec["method"] != "PLAIN" {
		t.Errorf("method = %q, want PLAIN", rec["method"])
	}
	if rec["username"] != "svc" || rec["password"] != "s3cr3t" {
		t.Errorf("PLAIN captured %q/%q, want svc/s3cr3t", rec["username"], rec["password"])
	}
	for k, want := range map[string]string{
		"product":         "AMQP 0.9.1 Client",
		"version":         "1.10.0",
		"platform":        "golang",
		"connection_name": "worker-1",
	} {
		if rec[k] != want {
			t.Errorf("%s = %q, want %q", k, rec[k], want)
		}
	}
}

// TestAMQPAMQPLAIN verifies the AMQPLAIN field-table response is decoded.
func TestAMQPAMQPLAIN(t *testing.T) {
	addr, got, conf := amqpTestServer(t)
	defer conf.Shutdown()

	conn := amqpDial(t, addr)
	defer conn.Close()

	// AMQPLAIN sends a field table without its length prefix.
	var tbl amqpEnc
	tbl.table([]amqpField{{"LOGIN", "guest"}, {"PASSWORD", "guest"}})
	resp := string(tbl.b[4:])
	conn.Write(amqpStartOkFrame([]amqpField{{"product", "pika"}}, "AMQPLAIN", resp))
	amqpExpectClose(t, conn, 403)

	rec := amqpWaitCred(t, got)
	if rec["method"] != "AMQPLAIN" {
		t.Errorf("method = %q, want AMQPLAIN", rec["method"])
	}
	if rec["username"] != "guest" || rec["password"] != "guest" {
		t.Errorf("AMQPLAIN captured %q/%q, want guest/guest", rec["username"], rec["password"])
	}
	if rec["product"] != "pika" {
		t.Errorf("product = %q, want pika", rec["product"])
	}
}

// TestAMQPBadHeader verifies an unsupported protocol header is answered with
// the supported header before the connection is closed.
func TestAMQPBadHeader(t *testing.T) {
	addr, _, conf := amqpTestServer(t)
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("AMQP\x00\x01\x00\x00"))

	b, _ := io.ReadAll(conn)
	if !bytes.Equal(b, amqpHeader) {
		t.Fatalf("reply %q, want %q", b, amqpHeader)
	}
}
