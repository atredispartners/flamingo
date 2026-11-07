package flamingo

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// pgTestServer spawns a PostgreSQL collector on a free port and returns the
// address plus a channel that receives captured credential records.
func pgTestServer(t *testing.T, withTLS bool) (string, chan map[string]string, *ConfPostgres) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfPostgres()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	if withTLS {
		conf.TLSCert, conf.TLSKey = imapTestCert(t)
	}

	if err := SpawnPostgres(conf); err != nil {
		t.Fatalf("SpawnPostgres failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func pgDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func pgWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// pgTestStartup builds a protocol 3.0 StartupMessage from ordered
// parameter pairs.
func pgTestStartup(params [][2]string) []byte {
	b := binary.BigEndian.AppendUint32(nil, 0)
	b = binary.BigEndian.AppendUint32(b, 3<<16)
	for _, kv := range params {
		b = append(b, kv[0]...)
		b = append(b, 0)
		b = append(b, kv[1]...)
		b = append(b, 0)
	}
	b = append(b, 0)
	binary.BigEndian.PutUint32(b[:4], uint32(len(b)))
	return b
}

// pgTestSSLRequest sends an SSLRequest and returns the server's one-byte answer.
func pgTestSSLRequest(t *testing.T, conn io.ReadWriter) byte {
	t.Helper()
	if _, err := conn.Write([]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}); err != nil {
		t.Fatalf("write SSLRequest: %s", err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("read SSLRequest reply: %s", err)
	}
	return reply[0]
}

// pgTestLogin sends the startup message, expects the cleartext password
// request, answers it, and verifies the 28P01 rejection.
func pgTestLogin(t *testing.T, conn io.ReadWriter, params [][2]string, password string) {
	t.Helper()
	if _, err := conn.Write(pgTestStartup(params)); err != nil {
		t.Fatalf("write startup: %s", err)
	}

	var auth [9]byte
	if _, err := io.ReadFull(conn, auth[:]); err != nil {
		t.Fatalf("read auth request: %s", err)
	}
	if !bytes.Equal(auth[:], []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("expected AuthenticationCleartextPassword, got %x", auth)
	}

	msg := []byte{'p', 0, 0, 0, 0}
	msg = append(msg, password...)
	msg = append(msg, 0)
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)-1))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write password: %s", err)
	}

	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read error header: %s", err)
	}
	if hdr[0] != 'E' {
		t.Fatalf("expected ErrorResponse, got %q", hdr[0])
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[1:])-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read error body: %s", err)
	}
	if !bytes.Contains(body, []byte("C28P01\x00")) {
		t.Errorf("error response lacks SQLSTATE 28P01: %q", body)
	}
	if !bytes.Contains(body, []byte("password authentication failed for user")) {
		t.Errorf("unexpected error message: %q", body)
	}
}

// pgTestCheck verifies the fields of a captured credential record.
func pgTestCheck(t *testing.T, rec map[string]string, user, db, app, password string) {
	t.Helper()
	if rec["_proto"] != "postgres" {
		t.Errorf("_proto = %q, want postgres", rec["_proto"])
	}
	if rec["method"] != "cleartext" {
		t.Errorf("method = %q, want cleartext", rec["method"])
	}
	if rec["username"] != user || rec["database"] != db || rec["password"] != password {
		t.Errorf("captured %q/%q/%q, want %s/%s/%s", rec["username"], rec["database"], rec["password"], user, db, password)
	}
	if rec["application_name"] != app {
		t.Errorf("application_name = %q, want %q", rec["application_name"], app)
	}
	if rec["_server"] == "" {
		t.Error("record missing _server")
	}
}

// TestPostgresCleartext verifies a plaintext startup and password exchange
// is captured and rejected with 28P01.
func TestPostgresCleartext(t *testing.T) {
	addr, got, conf := pgTestServer(t, false)
	defer conf.Shutdown()

	conn := pgDial(t, addr)
	defer conn.Close()

	pgTestLogin(t, conn, [][2]string{
		{"user", "alice"},
		{"database", "appdb"},
		{"application_name", "psql"},
		{"client_encoding", "UTF8"},
	}, "hunter2")

	rec := pgWaitCred(t, got)
	pgTestCheck(t, rec, "alice", "appdb", "psql", "hunter2")
	if rec["client_encoding"] != "UTF8" {
		t.Errorf("client_encoding = %q, want UTF8", rec["client_encoding"])
	}
}

// TestPostgresSSLRequest verifies an SSLRequest is accepted when a
// certificate is configured and credentials sent over TLS are captured.
func TestPostgresSSLRequest(t *testing.T) {
	addr, got, conf := pgTestServer(t, true)
	defer conf.Shutdown()

	conn := pgDial(t, addr)
	defer conn.Close()

	if reply := pgTestSSLRequest(t, conn); reply != 'S' {
		t.Fatalf("SSLRequest reply = %q, want S", reply)
	}
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %s", err)
	}

	pgTestLogin(t, tc, [][2]string{
		{"user", "tlsuser"},
		{"database", "tlsdb"},
	}, "tlspass")

	rec := pgWaitCred(t, got)
	pgTestCheck(t, rec, "tlsuser", "tlsdb", "", "tlspass")
}

// TestPostgresSSLRequestRefused verifies an SSLRequest is refused without a
// certificate and the client can continue in plaintext.
func TestPostgresSSLRequestRefused(t *testing.T) {
	addr, got, conf := pgTestServer(t, false)
	defer conf.Shutdown()

	conn := pgDial(t, addr)
	defer conn.Close()

	if reply := pgTestSSLRequest(t, conn); reply != 'N' {
		t.Fatalf("SSLRequest reply = %q, want N", reply)
	}

	pgTestLogin(t, conn, [][2]string{
		{"user", "plainuser"},
		{"database", "plaindb"},
		{"application_name", "pgcli"},
	}, "plainpass")

	rec := pgWaitCred(t, got)
	pgTestCheck(t, rec, "plainuser", "plaindb", "pgcli", "plainpass")
}
