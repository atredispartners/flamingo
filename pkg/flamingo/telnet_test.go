package flamingo

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// telnetTestServer spawns a Telnet collector on a free port and returns the
// address plus a channel that receives captured credential records.
func telnetTestServer(t *testing.T) (string, chan map[string]string, *ConfTelnet) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfTelnet()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnTelnet(conf); err != nil {
		t.Fatalf("SpawnTelnet failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

// telnetDial connects to the server and returns the connection and a reader.
func telnetDial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

// telnetReadUntil consumes server output up to and including the given text,
// swallowing IAC sequences and answering DO/WILL requests the way a minimal
// client would.
func telnetReadUntil(t *testing.T, conn net.Conn, r *bufio.Reader, want string) string {
	t.Helper()
	var text []byte
	for !strings.HasSuffix(string(text), want) {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("read failed waiting for %q (got %q): %s", want, text, err)
		}
		if b != telnetIAC {
			text = append(text, b)
			continue
		}
		cmd, err := r.ReadByte()
		if err != nil {
			t.Fatalf("read failed: %s", err)
		}
		switch cmd {
		case telnetWILL, telnetWONT, telnetDO, telnetDONT:
			opt, err := r.ReadByte()
			if err != nil {
				t.Fatalf("read failed: %s", err)
			}
			switch cmd {
			case telnetDO:
				conn.Write([]byte{telnetIAC, telnetWONT, opt})
			case telnetWILL:
				conn.Write([]byte{telnetIAC, telnetDONT, opt})
			}
		case telnetSB:
			for {
				b, err := r.ReadByte()
				if err != nil {
					t.Fatalf("read failed: %s", err)
				}
				if b == telnetIAC {
					if n, _ := r.ReadByte(); n == telnetSE {
						break
					}
				}
			}
		}
	}
	return string(text)
}

// telnetWaitCred returns the next captured record or fails the test.
func telnetWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

func TestTelnetLogin(t *testing.T) {
	addr, got, conf := telnetTestServer(t)
	defer conf.Shutdown()

	conn, r := telnetDial(t, addr)
	defer conn.Close()

	telnetReadUntil(t, conn, r, "login: ")
	conn.Write([]byte("admin\r\n"))
	telnetReadUntil(t, conn, r, "Password: ")
	conn.Write([]byte("hunter2\r\n"))
	if out := telnetReadUntil(t, conn, r, "Login incorrect\r\n"); !strings.Contains(out, "Login incorrect") {
		t.Errorf("unexpected response %q", out)
	}

	rec := telnetWaitCred(t, got)
	if rec["username"] != "admin" || rec["password"] != "hunter2" {
		t.Errorf("captured %q/%q, want admin/hunter2", rec["username"], rec["password"])
	}
	if rec["_proto"] != "telnet" {
		t.Errorf("_proto = %q, want telnet", rec["_proto"])
	}
	if rec["_server"] != "127.0.0.1:0" {
		t.Errorf("_server = %q, want 127.0.0.1:0", rec["_server"])
	}
	if _, ok := rec["terminal"]; ok {
		t.Errorf("terminal recorded without subnegotiation: %q", rec["terminal"])
	}
}

// TestTelnetMultipleAttempts verifies three attempts yield three records,
// including one with an empty password, and that the server then closes.
func TestTelnetMultipleAttempts(t *testing.T) {
	addr, got, conf := telnetTestServer(t)
	defer conf.Shutdown()

	conn, r := telnetDial(t, addr)
	defer conn.Close()

	creds := [][2]string{{"root", "root"}, {"admin", ""}, {"user", "1234"}}
	for _, c := range creds {
		telnetReadUntil(t, conn, r, "login: ")
		conn.Write([]byte(c[0] + "\r\n"))
		telnetReadUntil(t, conn, r, "Password: ")
		conn.Write([]byte(c[1] + "\r\n"))
		telnetReadUntil(t, conn, r, "Login incorrect\r\n")
	}

	for i, c := range creds {
		rec := telnetWaitCred(t, got)
		if rec["username"] != c[0] || rec["password"] != c[1] {
			t.Errorf("attempt %d captured %q/%q, want %q/%q", i+1, rec["username"], rec["password"], c[0], c[1])
		}
	}

	// The server closes after the third refusal, so the next read hits EOF.
	for {
		if _, err := r.ReadByte(); err != nil {
			if err != io.EOF {
				t.Errorf("expected EOF after third attempt, got %s", err)
			}
			break
		}
	}
}

// TestTelnetIACStripping verifies telnet commands embedded in the username
// are stripped, a terminal type subnegotiation is recorded, and bare LF and
// CR NUL line endings are accepted.
func TestTelnetIACStripping(t *testing.T) {
	addr, got, conf := telnetTestServer(t)
	defer conf.Shutdown()

	conn, r := telnetDial(t, addr)
	defer conn.Close()

	telnetReadUntil(t, conn, r, "login: ")
	conn.Write([]byte{
		telnetIAC, telnetWILL, telnetOptTermType,
		telnetIAC, telnetSB, telnetOptTermType, telnetTermTypeIs, 'X', 'T', 'E', 'R', 'M', telnetIAC, telnetSE,
		'a', 'd',
		telnetIAC, telnetDO, telnetOptEcho,
		'm', 'i',
		telnetIAC, telnetDONT, 5,
		'n',
		telnetIAC, telnetIAC,
		'\n',
	})
	telnetReadUntil(t, conn, r, "Password: ")
	conn.Write([]byte{'p', 'a', 's', 's', '\r', 0})
	telnetReadUntil(t, conn, r, "Login incorrect\r\n")

	rec := telnetWaitCred(t, got)
	if rec["username"] != `admin\xff` {
		t.Errorf("username = %q, want admin\\xff", rec["username"])
	}
	if rec["password"] != "pass" {
		t.Errorf("password = %q, want pass", rec["password"])
	}
	if rec["terminal"] != "XTERM" {
		t.Errorf("terminal = %q, want XTERM", rec["terminal"])
	}
}
