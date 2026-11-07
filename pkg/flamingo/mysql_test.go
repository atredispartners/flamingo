package flamingo

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// mysqlTestServer spawns a MySQL collector on a free port and returns the
// address plus a channel that receives captured credential records.
func mysqlTestServer(t *testing.T, withTLS bool) (string, chan map[string]string, *ConfMySQL) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfMySQL()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	if withTLS {
		conf.TLSCert, conf.TLSKey = imapTestCert(t)
	}

	if err := SpawnMySQL(conf); err != nil {
		t.Fatalf("SpawnMySQL failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func mysqlDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func mysqlWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// mysqlTestRead reads one packet and returns its payload and sequence number.
func mysqlTestRead(t *testing.T, conn io.Reader) ([]byte, byte) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("packet header: %s", err)
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	p := make([]byte, n)
	if _, err := io.ReadFull(conn, p); err != nil {
		t.Fatalf("packet body: %s", err)
	}
	return p, hdr[3]
}

// mysqlTestWrite frames a payload with the given sequence number and sends it.
func mysqlTestWrite(t *testing.T, conn io.Writer, seq byte, p []byte) {
	t.Helper()
	b := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}
	if _, err := conn.Write(append(b, p...)); err != nil {
		t.Fatalf("write: %s", err)
	}
}

// mysqlTestHandshake reads the HandshakeV10 and returns the salt and the
// server capability flags.
func mysqlTestHandshake(t *testing.T, conn io.Reader) ([]byte, uint32) {
	t.Helper()
	p, seq := mysqlTestRead(t, conn)
	if seq != 0 || len(p) < 1 || p[0] != 10 {
		t.Fatalf("unexpected handshake: seq %d, payload %x", seq, p)
	}
	end := bytes.IndexByte(p[1:], 0)
	if end < 0 {
		t.Fatal("handshake missing version terminator")
	}
	version := string(p[1 : 1+end])
	p = p[2+end:]
	if len(p) < 32 {
		t.Fatalf("handshake too short after version %q", version)
	}
	p = p[4:] // connection id
	salt := append([]byte{}, p[:8]...)
	p = p[9:] // first salt chunk plus filler
	capsLow := binary.LittleEndian.Uint16(p)
	p = p[5:] // lower caps, charset, status
	capsHigh := binary.LittleEndian.Uint16(p)
	p = p[2:]
	authLen := int(p[0])
	p = p[11:] // auth data length plus reserved
	if authLen != 21 || len(p) < 13 {
		t.Fatalf("unexpected auth data length %d", authLen)
	}
	salt = append(salt, p[:12]...)
	plugin := string(bytes.TrimRight(p[13:], "\x00"))
	if plugin != mysqlPluginNative {
		t.Fatalf("handshake plugin = %q, want %s", plugin, mysqlPluginNative)
	}
	return salt, uint32(capsHigh)<<16 | uint32(capsLow)
}

// mysqlTestCaps is the capability set a modern client presents.
const mysqlTestCaps = uint32(mysqlClientProtocol41 | mysqlClientSecureConnection |
	mysqlClientPluginAuth | mysqlClientConnectWithDB | mysqlClientConnectAttrs)

// mysqlTestResponse builds a HandshakeResponse41 with connection attributes.
func mysqlTestResponse(user, db, plugin string, auth []byte, attrs [][2]string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, mysqlTestCaps)
	b = binary.LittleEndian.AppendUint32(b, 16777216)
	b = append(b, 45) // utf8mb4_general_ci
	b = append(b, make([]byte, 23)...)
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, byte(len(auth)))
	b = append(b, auth...)
	b = append(b, db...)
	b = append(b, 0)
	b = append(b, plugin...)
	b = append(b, 0)
	var a []byte
	for _, kv := range attrs {
		a = append(a, byte(len(kv[0])))
		a = append(a, kv[0]...)
		a = append(a, byte(len(kv[1])))
		a = append(a, kv[1]...)
	}
	b = append(b, byte(len(a)))
	return append(b, a...)
}

// mysqlTestSSLRequest builds the 32-byte SSLRequest packet.
func mysqlTestSSLRequest() []byte {
	b := binary.LittleEndian.AppendUint32(nil, mysqlTestCaps|mysqlClientSSL)
	b = binary.LittleEndian.AppendUint32(b, 16777216)
	b = append(b, 45)
	return append(b, make([]byte, 23)...)
}

// mysqlScrambleNative is SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw))).
func mysqlScrambleNative(salt []byte, pw string) []byte {
	h1 := sha1.Sum([]byte(pw))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(salt)
	h.Write(h2[:])
	out := h.Sum(nil)
	for i := range out {
		out[i] ^= h1[i]
	}
	return out
}

// mysqlScrambleSHA256 is SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + salt).
func mysqlScrambleSHA256(salt []byte, pw string) []byte {
	h1 := sha256.Sum256([]byte(pw))
	h2 := sha256.Sum256(h1[:])
	h := sha256.New()
	h.Write(h2[:])
	h.Write(salt)
	out := h.Sum(nil)
	for i := range out {
		out[i] ^= h1[i]
	}
	return out
}

var mysqlTestAttrs = [][2]string{
	{"_client_name", "libmysql"},
	{"_client_version", "8.0.36"},
	{"_os", "Linux"},
	{"program_name", "mysqldump"},
}

// mysqlTestAuthSwitch reads the AuthSwitchRequest, answers it with the
// password, and verifies the server then rejects the login with 1045.
func mysqlTestAuthSwitch(t *testing.T, conn io.ReadWriter, password string) {
	t.Helper()
	p, seq := mysqlTestRead(t, conn)
	if len(p) < 1 || p[0] != 0xfe || string(p[1:]) != mysqlPluginClear+"\x00" {
		t.Fatalf("expected auth switch to %s, got %x", mysqlPluginClear, p)
	}
	mysqlTestWrite(t, conn, seq+1, append([]byte(password), 0))

	p, _ = mysqlTestRead(t, conn)
	if len(p) < 9 || p[0] != 0xff {
		t.Fatalf("expected ERR packet, got %x", p)
	}
	if code := binary.LittleEndian.Uint16(p[1:]); code != 1045 {
		t.Errorf("error code = %d, want 1045", code)
	}
	if msg := string(p[9:]); !strings.Contains(msg, "Access denied") || !strings.Contains(msg, "using password: YES") {
		t.Errorf("unexpected error message %q", msg)
	}
}

// TestMySQLNativePassword verifies the fixed salt is sent, the native
// scramble is recorded in hashcat 11200 form, and the cleartext auth switch
// yields a second record with the password.
func TestMySQLNativePassword(t *testing.T) {
	const secret = "hunter2"

	addr, got, conf := mysqlTestServer(t, false)
	defer conf.Shutdown()

	conn := mysqlDial(t, addr)
	defer conn.Close()

	salt, caps := mysqlTestHandshake(t, conn)
	if !bytes.Equal(salt, MySQLSalt) {
		t.Fatalf("handshake salt %x != MySQLSalt %x", salt, MySQLSalt)
	}
	if caps&mysqlClientSSL != 0 {
		t.Error("handshake advertises CLIENT_SSL without a certificate")
	}

	scramble := mysqlScrambleNative(salt, secret)
	mysqlTestWrite(t, conn, 1, mysqlTestResponse("alice", "appdb", mysqlPluginNative, scramble, mysqlTestAttrs))

	rec := mysqlWaitCred(t, got)
	if rec["_proto"] != "mysql" {
		t.Errorf("_proto = %q, want mysql", rec["_proto"])
	}
	if rec["username"] != "alice" || rec["database"] != "appdb" {
		t.Errorf("captured %q/%q, want alice/appdb", rec["username"], rec["database"])
	}
	if rec["method"] != mysqlPluginNative || rec["auth_plugin"] != mysqlPluginNative {
		t.Errorf("method/auth_plugin = %q/%q", rec["method"], rec["auth_plugin"])
	}
	if rec["salt"] != hex.EncodeToString(MySQLSalt) {
		t.Errorf("salt = %q", rec["salt"])
	}
	if rec["response"] != hex.EncodeToString(scramble) {
		t.Errorf("response = %q, want %x", rec["response"], scramble)
	}
	wantHash := fmt.Sprintf("$mysqlna$%x*%x", MySQLSalt, scramble)
	if rec["hashcat"] != wantHash {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantHash)
	}
	if rec["client_name"] != "libmysql" || rec["client_version"] != "8.0.36" || rec["program_name"] != "mysqldump" {
		t.Errorf("connection attributes not captured: %v", rec)
	}

	mysqlTestAuthSwitch(t, conn, secret)

	rec = mysqlWaitCred(t, got)
	if rec["method"] != mysqlPluginClear || rec["auth_plugin"] != mysqlPluginClear {
		t.Errorf("second record method/auth_plugin = %q/%q", rec["method"], rec["auth_plugin"])
	}
	if rec["username"] != "alice" || rec["password"] != secret {
		t.Errorf("cleartext captured %q/%q, want alice/%s", rec["username"], rec["password"], secret)
	}
	if _, ok := rec["hashcat"]; ok {
		t.Error("cleartext record carries a hashcat field")
	}
}

// TestMySQLCachingSHA2 verifies a caching_sha2_password response is recorded
// as raw bytes without a hashcat line and the cleartext switch still follows.
func TestMySQLCachingSHA2(t *testing.T) {
	const secret = "s3cr3t"

	addr, got, conf := mysqlTestServer(t, false)
	defer conf.Shutdown()

	conn := mysqlDial(t, addr)
	defer conn.Close()

	salt, _ := mysqlTestHandshake(t, conn)
	scramble := mysqlScrambleSHA256(salt, secret)
	mysqlTestWrite(t, conn, 1, mysqlTestResponse("bob", "", mysqlPluginSHA2, scramble, nil))

	rec := mysqlWaitCred(t, got)
	if rec["auth_plugin"] != mysqlPluginSHA2 || rec["response"] != hex.EncodeToString(scramble) {
		t.Errorf("sha2 record = %v", rec)
	}
	if _, ok := rec["hashcat"]; ok {
		t.Error("caching_sha2_password record carries a hashcat field")
	}

	mysqlTestAuthSwitch(t, conn, secret)

	rec = mysqlWaitCred(t, got)
	if rec["username"] != "bob" || rec["password"] != secret {
		t.Errorf("cleartext captured %q/%q, want bob/%s", rec["username"], rec["password"], secret)
	}
}

// TestMySQLSSLRequest verifies CLIENT_SSL is advertised with a certificate,
// an SSLRequest upgrades the connection in place, and credentials sent over
// TLS are captured.
func TestMySQLSSLRequest(t *testing.T) {
	const secret = "tlspass"

	addr, got, conf := mysqlTestServer(t, true)
	defer conf.Shutdown()

	conn := mysqlDial(t, addr)
	defer conn.Close()

	salt, caps := mysqlTestHandshake(t, conn)
	if caps&mysqlClientSSL == 0 {
		t.Fatal("handshake does not advertise CLIENT_SSL with a certificate")
	}
	mysqlTestWrite(t, conn, 1, mysqlTestSSLRequest())

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %s", err)
	}

	scramble := mysqlScrambleNative(salt, secret)
	mysqlTestWrite(t, tc, 2, mysqlTestResponse("tlsuser", "tlsdb", mysqlPluginNative, scramble, nil))

	rec := mysqlWaitCred(t, got)
	if rec["username"] != "tlsuser" || rec["database"] != "tlsdb" {
		t.Errorf("captured %q/%q, want tlsuser/tlsdb", rec["username"], rec["database"])
	}
	if rec["hashcat"] != fmt.Sprintf("$mysqlna$%x*%x", MySQLSalt, scramble) {
		t.Errorf("hashcat = %q", rec["hashcat"])
	}

	mysqlTestAuthSwitch(t, tc, secret)

	rec = mysqlWaitCred(t, got)
	if rec["username"] != "tlsuser" || rec["password"] != secret {
		t.Errorf("cleartext captured %q/%q, want tlsuser/%s", rec["username"], rec["password"], secret)
	}
}

// TestMySQLSwitchRefused verifies a client that drops the connection instead
// of answering the cleartext switch still leaves the scramble record.
func TestMySQLSwitchRefused(t *testing.T) {
	addr, got, conf := mysqlTestServer(t, false)
	defer conf.Shutdown()

	conn := mysqlDial(t, addr)
	salt, _ := mysqlTestHandshake(t, conn)
	scramble := mysqlScrambleNative(salt, "whatever")
	mysqlTestWrite(t, conn, 1, mysqlTestResponse("carol", "", mysqlPluginNative, scramble, nil))

	p, _ := mysqlTestRead(t, conn)
	if len(p) < 1 || p[0] != 0xfe {
		t.Fatalf("expected auth switch, got %x", p)
	}
	conn.Close()

	rec := mysqlWaitCred(t, got)
	if rec["username"] != "carol" || rec["response"] != hex.EncodeToString(scramble) {
		t.Errorf("scramble record = %v", rec)
	}
	select {
	case rec := <-got:
		t.Errorf("unexpected second record %v", rec)
	case <-time.After(200 * time.Millisecond):
	}
}
