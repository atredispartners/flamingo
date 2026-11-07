package flamingo

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// redisTestServer spawns a Redis collector on a free port and returns the
// address plus a channel that receives captured credential records.
func redisTestServer(t *testing.T) (string, chan map[string]string, *ConfRedis) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfRedis()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnRedis(conf); err != nil {
		t.Fatalf("SpawnRedis failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func redisDial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, bufio.NewReader(conn)
}

func redisWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// redisArray encodes args as a RESP multibulk command.
func redisArray(args ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	return sb.String()
}

// redisExpect sends a command and checks the reply prefix.
func redisExpect(t *testing.T, conn net.Conn, r *bufio.Reader, send, want string) {
	t.Helper()
	if _, err := conn.Write([]byte(send)); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, want) {
		t.Fatalf("sent %q, got %q (%v), want prefix %q", send, line, err, want)
	}
}

func TestRedisAuthPassword(t *testing.T) {
	addr, got, conf := redisTestServer(t)
	defer conf.Shutdown()

	conn, r := redisDial(t, addr)
	defer conn.Close()
	redisExpect(t, conn, r, redisArray("PING"), "-NOAUTH")
	redisExpect(t, conn, r, redisArray("AUTH", "hunter2"), "-WRONGPASS")

	rec := redisWaitCred(t, got)
	if rec["_proto"] != "redis" || rec["_type"] != "credential" {
		t.Errorf("record type/proto = %q/%q", rec["_type"], rec["_proto"])
	}
	if rec["username"] != "default" || rec["password"] != "hunter2" {
		t.Errorf("AUTH captured %q/%q, want default/hunter2", rec["username"], rec["password"])
	}

	// The session stays open for another attempt.
	redisExpect(t, conn, r, redisArray("AUTH", "second"), "-WRONGPASS")
	if rec := redisWaitCred(t, got); rec["password"] != "second" {
		t.Errorf("second AUTH captured %q, want second", rec["password"])
	}
	redisExpect(t, conn, r, redisArray("QUIT"), "+OK")
}

func TestRedisAuthUserPassword(t *testing.T) {
	addr, got, conf := redisTestServer(t)
	defer conf.Shutdown()

	conn, r := redisDial(t, addr)
	defer conn.Close()
	redisExpect(t, conn, r, redisArray("CLIENT", "SETNAME", "worker-1"), "-NOAUTH")
	redisExpect(t, conn, r, redisArray("CLIENT", "SETINFO", "LIB-NAME", "redis-py"), "-NOAUTH")
	redisExpect(t, conn, r, redisArray("CLIENT", "SETINFO", "LIB-VER", "5.0.1"), "-NOAUTH")
	redisExpect(t, conn, r, redisArray("AUTH", "alice", "s3cr3t"), "-WRONGPASS")

	rec := redisWaitCred(t, got)
	if rec["username"] != "alice" || rec["password"] != "s3cr3t" {
		t.Errorf("AUTH captured %q/%q, want alice/s3cr3t", rec["username"], rec["password"])
	}
	if rec["client_name"] != "worker-1" || rec["driver"] != "redis-py" || rec["driver_version"] != "5.0.1" {
		t.Errorf("client fields = %q/%q/%q", rec["client_name"], rec["driver"], rec["driver_version"])
	}
}

func TestRedisHelloAuth(t *testing.T) {
	addr, got, conf := redisTestServer(t)
	defer conf.Shutdown()

	conn, r := redisDial(t, addr)
	defer conn.Close()
	redisExpect(t, conn, r, redisArray("HELLO", "3"), "-NOAUTH")
	redisExpect(t, conn, r, redisArray("HELLO", "9"), "-NOPROTO")
	redisExpect(t, conn, r, redisArray("HELLO", "3", "AUTH", "bob", "pa ss", "SETNAME", "app"), "-WRONGPASS")

	rec := redisWaitCred(t, got)
	if rec["username"] != "bob" || rec["password"] != "pa ss" {
		t.Errorf("HELLO AUTH captured %q/%q, want bob/\"pa ss\"", rec["username"], rec["password"])
	}
	if rec["client_name"] != "app" {
		t.Errorf("client_name = %q, want app", rec["client_name"])
	}
}

func TestRedisInlineAuth(t *testing.T) {
	addr, got, conf := redisTestServer(t)
	defer conf.Shutdown()

	conn, r := redisDial(t, addr)
	defer conn.Close()
	redisExpect(t, conn, r, "AUTH secret\r\n", "-WRONGPASS")

	rec := redisWaitCred(t, got)
	if rec["username"] != "default" || rec["password"] != "secret" {
		t.Errorf("inline AUTH captured %q/%q, want default/secret", rec["username"], rec["password"])
	}
	if rec["_server"] == "" {
		t.Error("_server not set")
	}
}
