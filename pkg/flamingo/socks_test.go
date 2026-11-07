package flamingo

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// socksTestServer spawns a SOCKS collector on a free port and returns the
// address plus a channel that receives captured credential records.
func socksTestServer(t *testing.T) (string, chan map[string]string, *ConfSOCKS) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfSOCKS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnSOCKS(conf); err != nil {
		t.Fatalf("SpawnSOCKS failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

// socksExchange sends in, half-closes, and returns everything the server wrote.
func socksExchange(t *testing.T, addr string, in []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(in); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	conn.(*net.TCPConn).CloseWrite()
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read failed: %s", err)
	}
	return out
}

func socksWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// socksUserPass builds a SOCKS5 greeting offering no-auth and user/pass
// followed by an RFC 1929 login.
func socksUserPass(user, pass string) []byte {
	b := []byte{5, 2, 0, 2, 1, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

// socks4aRequest builds a SOCKS4a CONNECT with a user id and host name.
func socks4aRequest(user, host string, port uint16) []byte {
	b := binary.BigEndian.AppendUint16([]byte{4, 1}, port)
	b = append(b, 0, 0, 0, 1)
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, host...)
	return append(b, 0)
}

func TestSOCKS5UserPass(t *testing.T) {
	addr, got, conf := socksTestServer(t)
	defer conf.Shutdown()

	out := socksExchange(t, addr, socksUserPass("proxyuser", "proxypass"))
	if want := []byte{5, 2, 1, 1}; !bytes.Equal(out, want) {
		t.Fatalf("reply %x, want %x", out, want)
	}

	rec := socksWaitCred(t, got)
	if rec["_proto"] != "socks" || rec["_type"] != "credential" {
		t.Errorf("record type/proto = %q/%q", rec["_type"], rec["_proto"])
	}
	if rec["version"] != "5" {
		t.Errorf("version = %q, want 5", rec["version"])
	}
	if rec["username"] != "proxyuser" || rec["password"] != "proxypass" {
		t.Errorf("captured %q/%q, want proxyuser/proxypass", rec["username"], rec["password"])
	}
	if rec["_server"] == "" {
		t.Error("_server not set")
	}
}

func TestSOCKS4UserID(t *testing.T) {
	addr, got, conf := socksTestServer(t)
	defer conf.Shutdown()

	req := []byte{4, 1, 0, 80, 203, 0, 113, 5}
	req = append(req, "bot\x00"...)
	out := socksExchange(t, addr, req)
	if want := []byte{0, 0x5b, 0, 0, 0, 0, 0, 0}; !bytes.Equal(out, want) {
		t.Fatalf("reply %x, want %x", out, want)
	}

	rec := socksWaitCred(t, got)
	if rec["version"] != "4" {
		t.Errorf("version = %q, want 4", rec["version"])
	}
	if rec["username"] != "bot" {
		t.Errorf("username = %q, want bot", rec["username"])
	}
	if rec["target"] != "203.0.113.5:80" {
		t.Errorf("target = %q, want 203.0.113.5:80", rec["target"])
	}
	if _, ok := rec["password"]; ok {
		t.Error("SOCKS4 record should not carry a password")
	}
}

func TestSOCKS4aHostname(t *testing.T) {
	addr, got, conf := socksTestServer(t)
	defer conf.Shutdown()

	out := socksExchange(t, addr, socks4aRequest("mailer", "mail.example.org", 25))
	if want := []byte{0, 0x5b, 0, 0, 0, 0, 0, 0}; !bytes.Equal(out, want) {
		t.Fatalf("reply %x, want %x", out, want)
	}

	rec := socksWaitCred(t, got)
	if rec["version"] != "4a" {
		t.Errorf("version = %q, want 4a", rec["version"])
	}
	if rec["username"] != "mailer" {
		t.Errorf("username = %q, want mailer", rec["username"])
	}
	if rec["target"] != "mail.example.org:25" {
		t.Errorf("target = %q, want mail.example.org:25", rec["target"])
	}
}

// TestSOCKS5NoAuthTarget verifies an unauthenticated CONNECT is refused and
// produces no credential record.
func TestSOCKS5NoAuthTarget(t *testing.T) {
	addr, got, conf := socksTestServer(t)
	defer conf.Shutdown()

	req := []byte{5, 1, 0, 5, 1, 0, 3, byte(len("example.com"))}
	req = append(req, "example.com"...)
	req = binary.BigEndian.AppendUint16(req, 443)
	out := socksExchange(t, addr, req)
	if want := []byte{5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0}; !bytes.Equal(out, want) {
		t.Fatalf("reply %x, want %x", out, want)
	}

	select {
	case rec := <-got:
		t.Fatalf("unexpected credential record: %v", rec)
	case <-time.After(300 * time.Millisecond):
	}
}
