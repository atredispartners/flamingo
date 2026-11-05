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

// imapTestServer spawns an IMAP collector on a free port and returns the
// address plus a channel that receives captured credential records.
func imapTestServer(t *testing.T) (string, chan map[string]string, *ConfIMAP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfIMAP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnIMAP(conf); err != nil {
		t.Fatalf("SpawnIMAP failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func imapDial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	r.ReadString('\n') // greeting
	return conn, r
}

func imapWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

func TestIMAPLogin(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, _ := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 LOGIN alice \"s3cr3t pass\"\r\n")

	rec := imapWaitCred(t, got)
	if rec["username"] != "alice" || rec["password"] != "s3cr3t pass" {
		t.Errorf("LOGIN captured %q/%q, want alice/\"s3cr3t pass\"", rec["username"], rec["password"])
	}
	if rec["method"] != "LOGIN" {
		t.Errorf("method = %q, want LOGIN", rec["method"])
	}
}

// TestIMAPLoginLiteral verifies LOGIN arguments sent as synchronizing and
// non-synchronizing literals, as mail clients do for passwords containing
// special characters, are captured intact.
func TestIMAPLoginLiteral(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, r := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 LOGIN {5}\r\n")
	line, _ := r.ReadString('\n')
	if line[0] != '+' {
		t.Fatalf("expected continuation for literal, got %q", line)
	}
	fmt.Fprintf(conn, "alice {8+}\r\n")
	fmt.Fprintf(conn, "pa\"ss {}\r\n")

	rec := imapWaitCred(t, got)
	if rec["username"] != "alice" || rec["password"] != "pa\"ss {}" {
		t.Errorf("literal LOGIN captured %q/%q, want alice/pa\"ss {}", rec["username"], rec["password"])
	}
}

// TestIMAPLoginQuotedEscape verifies backslash escapes inside quoted LOGIN
// arguments are decoded.
func TestIMAPLoginQuotedEscape(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, _ := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 LOGIN \"al\\\"ice\" \"back\\\\slash\"\r\n")

	rec := imapWaitCred(t, got)
	if rec["username"] != "al\"ice" || rec["password"] != "back\\slash" {
		t.Errorf("quoted LOGIN captured %q/%q, want al\"ice/back\\slash", rec["username"], rec["password"])
	}
}

// TestIMAPRetryAfterFailure verifies the session stays open after a rejected
// AUTHENTICATE so a client's fallback attempt is captured too.
func TestIMAPRetryAfterFailure(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, r := imapDial(t, addr)
	defer conn.Close()
	blob := base64.StdEncoding.EncodeToString([]byte("\x00first\x00one"))
	fmt.Fprintf(conn, "a1 AUTHENTICATE PLAIN %s\r\n", blob)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "a1 NO") {
		t.Fatalf("expected a1 NO, got %q", line)
	}
	fmt.Fprintf(conn, "a2 LOGIN second two\r\n")

	first := imapWaitCred(t, got)
	second := imapWaitCred(t, got)
	if first["username"] != "first" || second["username"] != "second" {
		t.Errorf("captured %q then %q, want first then second", first["username"], second["username"])
	}
}

func TestIMAPAuthPlain(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, r := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 AUTHENTICATE PLAIN\r\n")
	r.ReadString('\n') // continuation "+"
	blob := base64.StdEncoding.EncodeToString([]byte("\x00bob\x00hunter2"))
	fmt.Fprintf(conn, "%s\r\n", blob)

	rec := imapWaitCred(t, got)
	if rec["username"] != "bob" || rec["password"] != "hunter2" {
		t.Errorf("PLAIN captured %q/%q, want bob/hunter2", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTHENTICATE PLAIN" {
		t.Errorf("method = %q, want AUTHENTICATE PLAIN", rec["method"])
	}
}

// TestIMAPAuthPlainInline verifies a SASL initial response sent inline with
// the AUTHENTICATE command (no continuation round-trip) is captured.
func TestIMAPAuthPlainInline(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, _ := imapDial(t, addr)
	defer conn.Close()
	blob := base64.StdEncoding.EncodeToString([]byte("\x00inlineuser\x00inlinepass"))
	fmt.Fprintf(conn, "a1 AUTHENTICATE PLAIN %s\r\n", blob)

	rec := imapWaitCred(t, got)
	if rec["username"] != "inlineuser" || rec["password"] != "inlinepass" {
		t.Errorf("inline PLAIN captured %q/%q, want inlineuser/inlinepass", rec["username"], rec["password"])
	}
}

// imapTestCert generates a throwaway self-signed cert/key PEM pair for the
// STARTTLS test.
func imapTestCert(t *testing.T) (string, string) {
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

// TestIMAPStartTLS verifies a client can upgrade a plaintext connection with
// STARTTLS and that credentials sent afterward are captured.
func TestIMAPStartTLS(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})
	conf := NewConfIMAP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.TLSCert, conf.TLSKey = imapTestCert(t)
	if err := SpawnIMAP(conf); err != nil {
		t.Fatalf("SpawnIMAP: %s", err)
	}
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", conf.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)
	r.ReadString('\n') // greeting
	fmt.Fprintf(conn, "a1 STARTTLS\r\n")
	r.ReadString('\n') // OK

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %s", err)
	}
	fmt.Fprintf(tc, "a2 LOGIN tlsuser tlspass\r\n")

	rec := imapWaitCred(t, got)
	if rec["username"] != "tlsuser" || rec["password"] != "tlspass" {
		t.Errorf("STARTTLS login captured %q/%q, want tlsuser/tlspass", rec["username"], rec["password"])
	}
}

// TestIMAPS verifies an implicit-TLS listener captures credentials and tags
// them with the imaps protocol name.
func TestIMAPS(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})
	conf := NewConfIMAP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.TLS = true
	conf.TLSCert, conf.TLSKey = imapTestCert(t)
	if err := SpawnIMAP(conf); err != nil {
		t.Fatalf("SpawnIMAP: %s", err)
	}
	defer conf.Shutdown()

	tc, err := tls.Dial("tcp", conf.listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %s", err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(tc)
	greeting, _ := r.ReadString('\n')
	if strings.Contains(greeting, "STARTTLS") {
		t.Errorf("imaps greeting advertises STARTTLS: %q", greeting)
	}
	fmt.Fprintf(tc, "a1 LOGIN imapsuser imapspass\r\n")

	rec := imapWaitCred(t, got)
	if rec["_proto"] != "imaps" {
		t.Errorf("_proto = %q, want imaps", rec["_proto"])
	}
	if rec["username"] != "imapsuser" || rec["password"] != "imapspass" {
		t.Errorf("IMAPS login captured %q/%q, want imapsuser/imapspass", rec["username"], rec["password"])
	}
}

// TestIMAPCramMD5 verifies the CRAM-MD5 HMAC is captured and matches what a
// real client computes from the known password.
func TestIMAPCramMD5(t *testing.T) {
	const secret = "monkey123"

	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, r := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 AUTHENTICATE CRAM-MD5\r\n")
	r.ReadString('\n') // base64 challenge continuation

	mac := hmac.New(md5.New, []byte(secret))
	mac.Write([]byte(IMAPCramChallenge))
	digest := hex.EncodeToString(mac.Sum(nil))
	resp := base64.StdEncoding.EncodeToString([]byte("cramuser " + digest))
	fmt.Fprintf(conn, "%s\r\n", resp)

	rec := imapWaitCred(t, got)
	if rec["username"] != "cramuser" {
		t.Errorf("CRAM-MD5 username = %q, want cramuser", rec["username"])
	}
	if rec["response"] != digest {
		t.Errorf("CRAM-MD5 captured hmac %q != computed %q", rec["response"], digest)
	}
	if rec["method"] != "AUTHENTICATE CRAM-MD5" {
		t.Errorf("method = %q", rec["method"])
	}
	// hashcat mode 10200 expects the $cram_md5$<b64 challenge>$<b64 response>
	// signature.
	wantHash := fmt.Sprintf("$cram_md5$%s$%s",
		base64.StdEncoding.EncodeToString([]byte(IMAPCramChallenge)), resp)
	if rec["hashcat"] != wantHash {
		t.Errorf("CRAM-MD5 hashcat = %q, want %q", rec["hashcat"], wantHash)
	}
}

func TestIMAPAuthLogin(t *testing.T) {
	addr, got, conf := imapTestServer(t)
	defer conf.Shutdown()

	conn, r := imapDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "a1 AUTHENTICATE LOGIN\r\n")
	r.ReadString('\n') // Username: prompt
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("carol")))
	r.ReadString('\n') // Password: prompt
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("p@ssw0rd")))

	rec := imapWaitCred(t, got)
	if rec["username"] != "carol" || rec["password"] != "p@ssw0rd" {
		t.Errorf("AUTH LOGIN captured %q/%q, want carol/p@ssw0rd", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTHENTICATE LOGIN" {
		t.Errorf("method = %q, want AUTHENTICATE LOGIN", rec["method"])
	}
}
