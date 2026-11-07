package flamingo

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// pop3TestServer spawns a POP3 collector on a free port and returns the
// address plus a channel that receives captured credential records.
func pop3TestServer(t *testing.T) (string, chan map[string]string, *ConfPOP3) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfPOP3()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnPOP3(conf); err != nil {
		t.Fatalf("SpawnPOP3 failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

// pop3Dial connects to the test server and returns the connection, a reader,
// and the greeting line.
func pop3Dial(t *testing.T, addr string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	greeting, _ := r.ReadString('\n')
	return conn, r, greeting
}

// pop3WaitCred returns the next captured record or fails the test.
func pop3WaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// pop3TestCert generates a throwaway self-signed cert/key PEM pair for the
// STLS test.
func pop3TestCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key gen: %s", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert create: %s", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	return certPEM, keyPEM
}

func TestPOP3UserPass(t *testing.T) {
	addr, got, conf := pop3TestServer(t)
	defer conf.Shutdown()

	conn, r, greeting := pop3Dial(t, addr)
	defer conn.Close()
	if !strings.HasPrefix(greeting, "+OK") || !strings.Contains(greeting, POP3CramChallenge) {
		t.Fatalf("unexpected greeting %q", greeting)
	}
	fmt.Fprintf(conn, "USER alice\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER reply = %q, want +OK", line)
	}
	fmt.Fprintf(conn, "PASS s3cr3t pass\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "-ERR [AUTH]") {
		t.Fatalf("PASS reply = %q, want -ERR [AUTH]", line)
	}

	rec := pop3WaitCred(t, got)
	if rec["username"] != "alice" || rec["password"] != "s3cr3t pass" {
		t.Errorf("USER/PASS captured %q/%q, want alice/\"s3cr3t pass\"", rec["username"], rec["password"])
	}
	if rec["method"] != "USER/PASS" {
		t.Errorf("method = %q, want USER/PASS", rec["method"])
	}
	if rec["_proto"] != "pop3" {
		t.Errorf("_proto = %q, want pop3", rec["_proto"])
	}
}

// TestPOP3APOP verifies the APOP digest computed from the greeting timestamp
// and a known password is captured along with the timestamp.
func TestPOP3APOP(t *testing.T) {
	const secret = "apopsecret"

	addr, got, conf := pop3TestServer(t)
	defer conf.Shutdown()

	conn, r, greeting := pop3Dial(t, addr)
	defer conn.Close()

	// The timestamp is the <...> token in the greeting.
	start, end := strings.Index(greeting, "<"), strings.LastIndex(greeting, ">")
	if start < 0 || end < start {
		t.Fatalf("greeting has no APOP timestamp: %q", greeting)
	}
	stamp := greeting[start : end+1]
	if stamp != POP3CramChallenge {
		t.Fatalf("greeting timestamp = %q, want %q", stamp, POP3CramChallenge)
	}

	sum := md5.Sum([]byte(stamp + secret))
	digest := hex.EncodeToString(sum[:])
	fmt.Fprintf(conn, "APOP dave %s\r\n", digest)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "-ERR") {
		t.Fatalf("APOP reply = %q, want -ERR", line)
	}

	rec := pop3WaitCred(t, got)
	if rec["method"] != "APOP" {
		t.Errorf("method = %q, want APOP", rec["method"])
	}
	if rec["username"] != "dave" {
		t.Errorf("APOP username = %q, want dave", rec["username"])
	}
	if rec["challenge"] != stamp {
		t.Errorf("APOP challenge = %q, want %q", rec["challenge"], stamp)
	}
	if rec["response"] != digest {
		t.Errorf("APOP response = %q, want %q", rec["response"], digest)
	}
	if want := digest + ":" + stamp; rec["hashcat"] != want {
		t.Errorf("APOP hashcat = %q, want %q", rec["hashcat"], want)
	}
}

func TestPOP3AuthPlain(t *testing.T) {
	addr, got, conf := pop3TestServer(t)
	defer conf.Shutdown()

	conn, r, _ := pop3Dial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH PLAIN\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "+ ") {
		t.Fatalf("expected continuation, got %q", line)
	}
	blob := base64.StdEncoding.EncodeToString([]byte("\x00bob\x00hunter2"))
	fmt.Fprintf(conn, "%s\r\n", blob)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "-ERR [AUTH]") {
		t.Fatalf("AUTH PLAIN reply = %q, want -ERR [AUTH]", line)
	}

	rec := pop3WaitCred(t, got)
	if rec["username"] != "bob" || rec["password"] != "hunter2" {
		t.Errorf("PLAIN captured %q/%q, want bob/hunter2", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTH PLAIN" {
		t.Errorf("method = %q, want AUTH PLAIN", rec["method"])
	}

	// An inline initial response is captured without a continuation.
	blob = base64.StdEncoding.EncodeToString([]byte("\x00inlineuser\x00inlinepass"))
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", blob)
	rec = pop3WaitCred(t, got)
	if rec["username"] != "inlineuser" || rec["password"] != "inlinepass" {
		t.Errorf("inline PLAIN captured %q/%q, want inlineuser/inlinepass", rec["username"], rec["password"])
	}
}

func TestPOP3AuthLogin(t *testing.T) {
	addr, got, conf := pop3TestServer(t)
	defer conf.Shutdown()

	conn, r, _ := pop3Dial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	r.ReadString('\n') // Username: prompt
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("carol")))
	r.ReadString('\n') // Password: prompt
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("p@ssw0rd")))

	rec := pop3WaitCred(t, got)
	if rec["username"] != "carol" || rec["password"] != "p@ssw0rd" {
		t.Errorf("AUTH LOGIN captured %q/%q, want carol/p@ssw0rd", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTH LOGIN" {
		t.Errorf("method = %q, want AUTH LOGIN", rec["method"])
	}
}

// TestPOP3AuthCramMD5 verifies the CRAM-MD5 HMAC is captured and matches what
// a real client computes from the known password, and that the hashcat mode
// 10200 string is formed correctly.
func TestPOP3AuthCramMD5(t *testing.T) {
	const secret = "monkey123"

	addr, got, conf := pop3TestServer(t)
	defer conf.Shutdown()

	conn, r, _ := pop3Dial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH CRAM-MD5\r\n")
	line, _ := r.ReadString('\n')
	challB64 := base64.StdEncoding.EncodeToString([]byte(POP3CramChallenge))
	if strings.TrimSpace(line) != "+ "+challB64 {
		t.Fatalf("challenge line = %q, want %q", strings.TrimSpace(line), "+ "+challB64)
	}

	mac := hmac.New(md5.New, []byte(secret))
	mac.Write([]byte(POP3CramChallenge))
	digest := hex.EncodeToString(mac.Sum(nil))
	resp := base64.StdEncoding.EncodeToString([]byte("cramuser " + digest))
	fmt.Fprintf(conn, "%s\r\n", resp)

	rec := pop3WaitCred(t, got)
	if rec["username"] != "cramuser" {
		t.Errorf("CRAM-MD5 username = %q, want cramuser", rec["username"])
	}
	if rec["challenge"] != POP3CramChallenge {
		t.Errorf("CRAM-MD5 challenge = %q, want %q", rec["challenge"], POP3CramChallenge)
	}
	if rec["response"] != digest {
		t.Errorf("CRAM-MD5 captured hmac %q != computed %q", rec["response"], digest)
	}
	if rec["method"] != "AUTH CRAM-MD5" {
		t.Errorf("method = %q, want AUTH CRAM-MD5", rec["method"])
	}
	wantHash := fmt.Sprintf("$cram_md5$%s$%s", challB64, resp)
	if rec["hashcat"] != wantHash {
		t.Errorf("CRAM-MD5 hashcat = %q, want %q", rec["hashcat"], wantHash)
	}
}

// TestPOP3STLS verifies a client can upgrade a plaintext connection with STLS
// and that USER/PASS sent afterward is captured.
func TestPOP3STLS(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})
	conf := NewConfPOP3()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.TLSCert, conf.TLSKey = pop3TestCert(t)
	if err := SpawnPOP3(conf); err != nil {
		t.Fatalf("SpawnPOP3: %s", err)
	}
	defer conf.Shutdown()

	conn, r, _ := pop3Dial(t, conf.listener.Addr().String())
	defer conn.Close()

	fmt.Fprintf(conn, "CAPA\r\n")
	sawSTLS := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("CAPA read: %s", err)
		}
		line = strings.TrimSpace(line)
		if line == "STLS" {
			sawSTLS = true
		}
		if line == "." {
			break
		}
	}
	if !sawSTLS {
		t.Fatal("CAPA did not advertise STLS")
	}

	fmt.Fprintf(conn, "STLS\r\n")
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STLS reply = %q, want +OK", line)
	}

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %s", err)
	}
	tr := bufio.NewReader(tc)
	fmt.Fprintf(tc, "USER tlsuser\r\n")
	tr.ReadString('\n')
	fmt.Fprintf(tc, "PASS tlspass\r\n")

	rec := pop3WaitCred(t, got)
	if rec["username"] != "tlsuser" || rec["password"] != "tlspass" {
		t.Errorf("STLS USER/PASS captured %q/%q, want tlsuser/tlspass", rec["username"], rec["password"])
	}
	if rec["method"] != "USER/PASS" {
		t.Errorf("method = %q, want USER/PASS", rec["method"])
	}
}

// TestPOP3S verifies an implicit-TLS listener captures credentials and tags
// them with the pop3s protocol name without offering STLS.
func TestPOP3S(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})
	conf := NewConfPOP3()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.TLS = true
	conf.TLSCert, conf.TLSKey = pop3TestCert(t)
	if err := SpawnPOP3(conf); err != nil {
		t.Fatalf("SpawnPOP3: %s", err)
	}
	defer conf.Shutdown()

	tc, err := tls.Dial("tcp", conf.listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %s", err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(tc)
	r.ReadString('\n') // greeting

	fmt.Fprintf(tc, "CAPA\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("CAPA read: %s", err)
		}
		line = strings.TrimSpace(line)
		if line == "STLS" {
			t.Error("pop3s CAPA advertises STLS")
		}
		if line == "." {
			break
		}
	}

	fmt.Fprintf(tc, "USER pop3suser\r\n")
	r.ReadString('\n')
	fmt.Fprintf(tc, "PASS pop3spass\r\n")

	rec := pop3WaitCred(t, got)
	if rec["_proto"] != "pop3s" {
		t.Errorf("_proto = %q, want pop3s", rec["_proto"])
	}
	if rec["username"] != "pop3suser" || rec["password"] != "pop3spass" {
		t.Errorf("POP3S captured %q/%q, want pop3suser/pop3spass", rec["username"], rec["password"])
	}
}
