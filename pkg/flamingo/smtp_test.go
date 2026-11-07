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
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// smtpTestServer spawns an SMTP collector on a free port and returns the
// address plus a channel that receives captured credential records. The
// setup callback adjusts the configuration before the listener starts.
func smtpTestServer(t *testing.T, setup func(*ConfSMTP)) (string, chan map[string]string, *ConfSMTP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfSMTP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	if setup != nil {
		setup(conf)
	}

	if err := SpawnSMTP(conf); err != nil {
		t.Fatalf("SpawnSMTP failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

// smtpReadReply reads a possibly multi-line SMTP reply and returns its lines.
func smtpReadReply(t *testing.T, r *bufio.Reader) []string {
	t.Helper()
	var lines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read reply: %s", err)
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) < 4 || line[3] != '-' {
			return lines
		}
	}
}

// smtpEHLO sends EHLO and returns the extension lines from the reply.
func smtpEHLO(t *testing.T, conn net.Conn, r *bufio.Reader, name string) []string {
	t.Helper()
	fmt.Fprintf(conn, "EHLO %s\r\n", name)
	lines := smtpReadReply(t, r)
	if !strings.HasPrefix(lines[0], "250") {
		t.Fatalf("EHLO rejected: %q", lines[0])
	}
	return lines
}

// smtpDial connects, consumes the banner, and completes an EHLO exchange.
func smtpDial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	banner := smtpReadReply(t, r)
	if !strings.HasPrefix(banner[0], "220 ") {
		t.Fatalf("unexpected banner %q", banner[0])
	}
	smtpEHLO(t, conn, r, "client.example")
	return conn, r
}

func smtpWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// smtpExpect reads one reply line and checks its prefix.
func smtpExpect(t *testing.T, r *bufio.Reader, prefix string) string {
	t.Helper()
	lines := smtpReadReply(t, r)
	if !strings.HasPrefix(lines[0], prefix) {
		t.Fatalf("expected reply %q, got %q", prefix, lines[0])
	}
	return lines[0]
}

// smtpTestCert generates a throwaway self-signed cert/key PEM pair for the
// TLS tests.
func smtpTestCert(t *testing.T) (string, string) {
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

func TestSMTPAuthPlain(t *testing.T) {
	addr, got, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH PLAIN\r\n")
	smtpExpect(t, r, "334")
	blob := base64.StdEncoding.EncodeToString([]byte("\x00bob\x00hunter2"))
	fmt.Fprintf(conn, "%s\r\n", blob)
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["username"] != "bob" || rec["password"] != "hunter2" {
		t.Errorf("PLAIN captured %q/%q, want bob/hunter2", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTH PLAIN" {
		t.Errorf("method = %q, want AUTH PLAIN", rec["method"])
	}
	if rec["ehlo"] != "client.example" {
		t.Errorf("ehlo = %q, want client.example", rec["ehlo"])
	}
	if rec["_proto"] != "smtp" {
		t.Errorf("_proto = %q, want smtp", rec["_proto"])
	}
}

// TestSMTPAuthPlainInline verifies a SASL initial response sent with the
// AUTH command is captured, and that the session survives a rejection so a
// second attempt is captured too.
func TestSMTPAuthPlainInline(t *testing.T) {
	addr, got, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	blob := base64.StdEncoding.EncodeToString([]byte("authz\x00inlineuser\x00inlinepass"))
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", blob)
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["username"] != "inlineuser" || rec["password"] != "inlinepass" {
		t.Errorf("inline PLAIN captured %q/%q, want inlineuser/inlinepass", rec["username"], rec["password"])
	}

	blob = base64.StdEncoding.EncodeToString([]byte("\x00second\x00two"))
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", blob)
	smtpExpect(t, r, "535 5.7.8")
	rec = smtpWaitCred(t, got)
	if rec["username"] != "second" || rec["password"] != "two" {
		t.Errorf("retry captured %q/%q, want second/two", rec["username"], rec["password"])
	}
}

func TestSMTPAuthLogin(t *testing.T) {
	addr, got, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	if line := smtpExpect(t, r, "334 "); line != "334 VXNlcm5hbWU6" {
		t.Errorf("username prompt = %q", line)
	}
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("carol")))
	if line := smtpExpect(t, r, "334 "); line != "334 UGFzc3dvcmQ6" {
		t.Errorf("password prompt = %q", line)
	}
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("p@ssw0rd")))
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["username"] != "carol" || rec["password"] != "p@ssw0rd" {
		t.Errorf("AUTH LOGIN captured %q/%q, want carol/p@ssw0rd", rec["username"], rec["password"])
	}
	if rec["method"] != "AUTH LOGIN" {
		t.Errorf("method = %q, want AUTH LOGIN", rec["method"])
	}
}

// TestSMTPAuthLoginCancel verifies a "*" cancellation is answered with 501
// and leaves the session usable.
func TestSMTPAuthLoginCancel(t *testing.T) {
	addr, _, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	smtpExpect(t, r, "334 ")
	fmt.Fprintf(conn, "*\r\n")
	smtpExpect(t, r, "501 5.7.0")
	fmt.Fprintf(conn, "NOOP\r\n")
	smtpExpect(t, r, "250")
}

// TestSMTPAuthCramMD5 verifies the CRAM-MD5 HMAC is captured and matches
// what a real client computes from the known password.
func TestSMTPAuthCramMD5(t *testing.T) {
	const secret = "monkey123"

	addr, got, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH CRAM-MD5\r\n")
	line := smtpExpect(t, r, "334 ")
	challenge, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "334 "))
	if err != nil || string(challenge) != SMTPCramChallenge {
		t.Fatalf("challenge = %q (%v), want %q", challenge, err, SMTPCramChallenge)
	}

	mac := hmac.New(md5.New, []byte(secret))
	mac.Write(challenge)
	digest := hex.EncodeToString(mac.Sum(nil))
	resp := base64.StdEncoding.EncodeToString([]byte("cramuser " + digest))
	fmt.Fprintf(conn, "%s\r\n", resp)
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["username"] != "cramuser" {
		t.Errorf("CRAM-MD5 username = %q, want cramuser", rec["username"])
	}
	if rec["challenge"] != SMTPCramChallenge {
		t.Errorf("CRAM-MD5 challenge = %q", rec["challenge"])
	}
	if rec["response"] != digest {
		t.Errorf("CRAM-MD5 captured hmac %q != computed %q", rec["response"], digest)
	}
	if rec["method"] != "AUTH CRAM-MD5" {
		t.Errorf("method = %q", rec["method"])
	}
	// hashcat mode 10200 expects $cram_md5$<b64 challenge>$<b64 response>
	wantHash := fmt.Sprintf("$cram_md5$%s$%s",
		base64.StdEncoding.EncodeToString([]byte(SMTPCramChallenge)), resp)
	if rec["hashcat"] != wantHash {
		t.Errorf("CRAM-MD5 hashcat = %q, want %q", rec["hashcat"], wantHash)
	}
}

// TestSMTPStartTLS verifies a client can upgrade a plaintext connection with
// STARTTLS and that credentials sent afterward are captured.
func TestSMTPStartTLS(t *testing.T) {
	certPEM, keyPEM := smtpTestCert(t)
	addr, got, conf := smtpTestServer(t, func(c *ConfSMTP) {
		c.TLSCert, c.TLSKey = certPEM, keyPEM
	})
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)
	smtpExpect(t, r, "220 ")
	ehlo := strings.Join(smtpEHLO(t, conn, r, "tls.example"), "\n")
	if !strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("plaintext EHLO does not advertise STARTTLS: %q", ehlo)
	}
	fmt.Fprintf(conn, "STARTTLS\r\n")
	smtpExpect(t, r, "220 2.0.0")

	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %s", err)
	}
	tr := bufio.NewReader(tc)
	ehlo = strings.Join(smtpEHLO(t, tc, tr, "tls.example"), "\n")
	if strings.Contains(ehlo, "STARTTLS") {
		t.Errorf("encrypted EHLO still advertises STARTTLS: %q", ehlo)
	}
	blob := base64.StdEncoding.EncodeToString([]byte("\x00tlsuser\x00tlspass"))
	fmt.Fprintf(tc, "AUTH PLAIN %s\r\n", blob)
	smtpExpect(t, tr, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["username"] != "tlsuser" || rec["password"] != "tlspass" {
		t.Errorf("STARTTLS login captured %q/%q, want tlsuser/tlspass", rec["username"], rec["password"])
	}
	if rec["_proto"] != "smtp" {
		t.Errorf("_proto = %q, want smtp", rec["_proto"])
	}
}

// TestSMTPS verifies an implicit-TLS listener captures credentials and tags
// them with the smtps protocol name.
func TestSMTPS(t *testing.T) {
	certPEM, keyPEM := smtpTestCert(t)
	addr, got, conf := smtpTestServer(t, func(c *ConfSMTP) {
		c.TLS = true
		c.TLSCert, c.TLSKey = certPEM, keyPEM
	})
	defer conf.Shutdown()

	tc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial: %s", err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(tc)
	smtpExpect(t, r, "220 ")
	ehlo := strings.Join(smtpEHLO(t, tc, r, "smtps.example"), "\n")
	if strings.Contains(ehlo, "STARTTLS") {
		t.Errorf("smtps EHLO advertises STARTTLS: %q", ehlo)
	}
	fmt.Fprintf(tc, "AUTH LOGIN %s\r\n", base64.StdEncoding.EncodeToString([]byte("smtpsuser")))
	smtpExpect(t, r, "334 ")
	fmt.Fprintf(tc, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("smtpspass")))
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["_proto"] != "smtps" {
		t.Errorf("_proto = %q, want smtps", rec["_proto"])
	}
	if rec["username"] != "smtpsuser" || rec["password"] != "smtpspass" {
		t.Errorf("SMTPS login captured %q/%q, want smtpsuser/smtpspass", rec["username"], rec["password"])
	}
}

// TestSMTPCommands verifies the non-authentication commands answer as a
// Postfix server would without accepting mail.
func TestSMTPCommands(t *testing.T) {
	addr, _, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	steps := []struct{ send, want string }{
		{"NOOP", "250"},
		{"RSET", "250"},
		{"HELP", "214"},
		{"MAIL FROM:<a@b.example>", "530 5.7.0"},
		{"RCPT TO:<c@d.example>", "503"},
		{"DATA", "503"},
		{"STARTTLS", "454"},
		{"BOGUS", "502"},
		{"AUTH XOAUTH2 abc", "535"},
		{"QUIT", "221"},
	}
	for _, step := range steps {
		fmt.Fprintf(conn, "%s\r\n", step.send)
		if line := smtpReadReply(t, r)[0]; !strings.HasPrefix(line, step.want) {
			t.Errorf("%s: got %q, want prefix %q", step.send, line, step.want)
		}
	}
}

// smtpUTF16 encodes a string as little-endian UTF-16 without a terminator.
func smtpUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// smtpNTLMNegotiate builds a minimal NEGOTIATE (type 1) message.
func smtpNTLMNegotiate() []byte {
	m := make([]byte, 32)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:], 1)
	binary.LittleEndian.PutUint32(m[12:], 0x00000001|0x00000200|0x00080000)
	return m
}

// smtpNTLMAuthenticate builds an AUTHENTICATE (type 3) message carrying an
// NTLMv2 response made of the given proof and blob.
func smtpNTLMAuthenticate(user, domain, ws string, proof, blob []byte) []byte {
	m := make([]byte, 88)
	copy(m, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(m[8:], 3)
	binary.LittleEndian.PutUint32(m[60:], 0x00000001|0x00000200|0x02000000)
	copy(m[64:], []byte{10, 0, 0x61, 0x4a, 0, 0, 0, 15})
	put := func(at int, v []byte) {
		binary.LittleEndian.PutUint16(m[at:], uint16(len(v)))
		binary.LittleEndian.PutUint16(m[at+2:], uint16(len(v)))
		binary.LittleEndian.PutUint32(m[at+4:], uint32(len(m)))
		m = append(m, v...)
	}
	put(12, make([]byte, 24))
	put(20, append(append([]byte{}, proof...), blob...))
	put(28, smtpUTF16(domain))
	put(36, smtpUTF16(user))
	put(44, smtpUTF16(ws))
	put(52, nil)
	return m
}

// TestSMTPAuthNTLM verifies the NTLM exchange returns the fixed challenge and
// records the NTLMv2 response in hashcat form.
func TestSMTPAuthNTLM(t *testing.T) {
	addr, got, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH NTLM\r\n")
	smtpExpect(t, r, "334")
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString(smtpNTLMNegotiate()))
	line := smtpExpect(t, r, "334 ")
	if strings.TrimPrefix(line, "334 ") != NTLMChallenge {
		t.Fatalf("type 2 challenge = %q, want NTLMChallenge", line)
	}

	proof := make([]byte, 16)
	for i := range proof {
		proof[i] = byte(0xa0 + i)
	}
	// Blob: response type 1.1, reserved, timestamp, client challenge,
	// reserved, then an empty AV pair list.
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = append(blob, []byte{1, 2, 3, 4, 5, 6, 7, 8}...)
	blob = append(blob, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, 0, 0, 0, 0)
	type3 := smtpNTLMAuthenticate("ntlmuser", "CORP", "WS01", proof, blob)
	fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString(type3))
	smtpExpect(t, r, "535 5.7.8")

	rec := smtpWaitCred(t, got)
	if rec["method"] != "AUTH NTLM" {
		t.Errorf("method = %q, want AUTH NTLM", rec["method"])
	}
	if rec["username"] != "ntlmuser" || rec["domain"] != "CORP" {
		t.Errorf("NTLM captured %q/%q, want ntlmuser/CORP", rec["username"], rec["domain"])
	}
	wantPrefix := "ntlmuser::CORP:1122334455667788:" + hex.EncodeToString(proof) + ":"
	if !strings.HasPrefix(rec["hashcat"], wantPrefix) {
		t.Errorf("NTLM hashcat = %q, want prefix %q", rec["hashcat"], wantPrefix)
	}
	if !strings.HasPrefix(strings.TrimPrefix(rec["hashcat"], wantPrefix), hex.EncodeToString(blob[:len(blob)-1])) {
		t.Errorf("NTLM hashcat blob mismatch in %q", rec["hashcat"])
	}
}

// TestSMTPAuthNTLMInline verifies a NEGOTIATE sent as the AUTH initial
// response skips the empty continuation and still yields the challenge.
func TestSMTPAuthNTLMInline(t *testing.T) {
	addr, _, conf := smtpTestServer(t, nil)
	defer conf.Shutdown()

	conn, r := smtpDial(t, addr)
	defer conn.Close()
	fmt.Fprintf(conn, "AUTH NTLM %s\r\n", base64.StdEncoding.EncodeToString(smtpNTLMNegotiate()))
	line := smtpExpect(t, r, "334 ")
	if strings.TrimPrefix(line, "334 ") != NTLMChallenge {
		t.Fatalf("type 2 challenge = %q, want NTLMChallenge", line)
	}
	fmt.Fprintf(conn, "*\r\n")
	smtpExpect(t, r, "501 5.7.0")
}
