package flamingo

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/atredispartners/flamingo/pkg/asn1-ber"
	"github.com/atredispartners/flamingo/pkg/ldap"
)

// The LDAP tests drive a spawned listener over a real socket with bind
// requests built here from BER primitives. pkg/ldap's own tests shell out to a
// system ldapsearch and cannot run on every machine, so nothing here depends
// on an external client.

// ldapTestServer spawns an LDAP collector on a free port and returns the
// address plus a channel that receives captured credential records.
func ldapTestServer(t *testing.T) (string, chan map[string]string) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfLDAP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnLDAP(conf); err != nil {
		t.Fatalf("SpawnLDAP failed: %s", err)
	}
	t.Cleanup(func() {
		conf.Shutdown()
		rw.Done()
	})
	return conf.listener.Addr().String(), got
}

func ldapTestDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func ldapTestWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// ldapTestSimpleAuth builds the simple [0] AuthenticationChoice.
func ldapTestSimpleAuth(password string) *ber.Packet {
	return ber.NewString(ber.ClassContext, ber.TypePrimitive, ldap.LDAPBindAuthSimple, password, "simple")
}

// ldapTestSASLAuth builds the sasl [3] AuthenticationChoice, which is a
// SaslCredentials sequence of a mechanism and an optional credential.
func ldapTestSASLAuth(mechanism string, credentials []byte) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.LDAPBindAuthSASL, nil, "sasl")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "mechanism"))
	if credentials != nil {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(credentials), "credentials"))
	}
	return p
}

// ldapTestBind sends a bind request and returns the response result code and
// serverSaslCreds.
func ldapTestBind(t *testing.T, conn net.Conn, messageID uint64, dn string, auth *ber.Packet) (uint64, []byte) {
	t.Helper()

	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind Request")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Name"))
	req.AppendChild(auth)

	pkt := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	pkt.AppendChild(req)

	if _, err := conn.Write(pkt.Bytes()); err != nil {
		t.Fatalf("write bind request: %s", err)
	}
	return ldapTestReadBindResponse(t, conn, messageID)
}

// Responses are decoded here rather than with pkg/asn1-ber: that decoder
// rejects a zero-length element that ends a buffer ("packet too short"), which
// every bind response hits on its empty errorMessage. Real clients parse these
// responses, so the tests do their own reading instead of depending on the
// vendored decoder's quirk.

// ldapTestElement is one BER tag-length-value element.
type ldapTestElement struct {
	tag  byte
	body []byte
}

// ldapTestReadElement reads one BER element, definite length only.
func ldapTestReadElement(r io.Reader) (ldapTestElement, error) {
	var e ldapTestElement
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return e, err
	}
	e.tag = hdr[0]
	n := int(hdr[1])
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 4 {
			return e, fmt.Errorf("unsupported BER length form 0x%02x", hdr[1])
		}
		lb := make([]byte, count)
		if _, err := io.ReadFull(r, lb); err != nil {
			return e, err
		}
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	e.body = make([]byte, n)
	if _, err := io.ReadFull(r, e.body); err != nil {
		return e, err
	}
	return e, nil
}

// ldapTestElements splits a constructed element's body into its elements.
func ldapTestElements(body []byte) ([]ldapTestElement, error) {
	r := bytes.NewReader(body)
	var out []ldapTestElement
	for r.Len() > 0 {
		e, err := ldapTestReadElement(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// ldapTestInt decodes a BER integer or enumerated value.
func ldapTestInt(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// ldapTestBindResponse reads one LDAP message and decodes it as a bind
// response: message ID, result code and the optional serverSaslCreds [7].
func ldapTestBindResponse(r io.Reader) (msgID uint64, code uint64, creds []byte, err error) {
	msg, err := ldapTestReadElement(r)
	if err != nil {
		return 0, 0, nil, err
	}
	if msg.tag != 0x30 {
		return 0, 0, nil, fmt.Errorf("message tag 0x%02x, want a sequence", msg.tag)
	}
	parts, err := ldapTestElements(msg.body)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("malformed LDAP message: %s", err)
	}
	if len(parts) < 2 {
		return 0, 0, nil, fmt.Errorf("LDAP message has %d elements", len(parts))
	}
	msgID = ldapTestInt(parts[0].body)
	// BindResponse is [APPLICATION 1] constructed, which is tag byte 0x61.
	if parts[1].tag != 0x61 {
		return msgID, 0, nil, fmt.Errorf("response tag 0x%02x, want a bind response", parts[1].tag)
	}
	fields, err := ldapTestElements(parts[1].body)
	if err != nil {
		return msgID, 0, nil, fmt.Errorf("malformed bind response: %s", err)
	}
	if len(fields) < 3 {
		return msgID, 0, nil, fmt.Errorf("bind response has %d fields", len(fields))
	}
	code = ldapTestInt(fields[0].body)
	for _, f := range fields[3:] {
		if f.tag == 0x87 { // serverSaslCreds [7], context primitive
			creds = f.body
		}
	}
	return msgID, code, creds, nil
}

// ldapTestReadBindResponse reads one bind response and returns its result code
// and serverSaslCreds.
func ldapTestReadBindResponse(t *testing.T, conn net.Conn, messageID uint64) (uint64, []byte) {
	t.Helper()
	id, code, creds, err := ldapTestBindResponse(conn)
	if err != nil {
		t.Fatalf("read bind response: %s", err)
	}
	if id != messageID {
		t.Fatalf("bind response message ID %d, want %d", id, messageID)
	}
	return code, creds
}

// ldapTestNegotiate is a minimal NTLMSSP NEGOTIATE message.
func ldapTestNegotiate() []byte {
	return smbTestNegotiateToken()
}

// TestLDAPSimpleBind checks that the cleartext simple bind this listener has
// always captured still works unchanged.
func TestLDAPSimpleBind(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, creds := ldapTestBind(t, conn, 1, "cn=alice,dc=corp,dc=local", ldapTestSimpleAuth("Password1"))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}
	if creds != nil {
		t.Errorf("simple bind response carries serverSaslCreds %x", creds)
	}

	rec := ldapTestWaitCred(t, got)
	if rec["username"] != "cn=alice,dc=corp,dc=local" {
		t.Errorf("username = %q", rec["username"])
	}
	if rec["password"] != "Password1" {
		t.Errorf("password = %q", rec["password"])
	}
	if rec["_proto"] != "ldap" || rec["_type"] != "credential" {
		t.Errorf("_proto = %q, _type = %q", rec["_proto"], rec["_type"])
	}
	if _, ok := rec["method"]; ok {
		t.Errorf("simple bind record gained a method field: %q", rec["method"])
	}
	if !strings.HasPrefix(rec["_host"], "127.0.0.1:") {
		t.Errorf("_host = %q, want the client address", rec["_host"])
	}
}

// TestLDAPSASLNTLM runs the two-round-trip GSS-SPNEGO/NTLM bind with a genuine
// NetNTLMv2 response and checks the challenge, the result codes and the
// recorded hashcat 5600 line.
func TestLDAPSASLNTLM(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	// Round one: NEGOTIATE wrapped in a SPNEGO negTokenInit, as a Windows
	// client sends it.
	negotiate := smbSPNEGONegTokenResp(ldapTestNegotiate())
	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("GSS-SPNEGO", negotiate))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("round one result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	if !ldapIsSPNEGO(creds) {
		t.Fatalf("serverSaslCreds is not a SPNEGO token: %x", creds)
	}
	challenge := FindNTLMSSP(creds)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("serverSaslCreds carries no CHALLENGE: %x", creds)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("challenge %x, want %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	// Round two: a real NTLMv2 AUTHENTICATE computed against that challenge.
	info := ntlmSecBuf(challenge, 40)
	if len(info) == 0 {
		t.Fatal("CHALLENGE carries no target info")
	}
	blob := ntlmTestV2Blob(info, false)
	proof := ntlmTestV2Proof("Password1", "alice", "CORP", NTLMConf.Challenge[:], blob)
	auth := ntlmTestAuthMsg("alice", "CORP", "WS01", nil, append(proof, blob...), nil, 0)

	code, creds = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("GSS-SPNEGO", smbSPNEGONegTokenResp(auth)))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("round two result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}
	if creds != nil {
		t.Errorf("final bind response carries serverSaslCreds %x", creds)
	}

	rec := ldapTestWaitCred(t, got)
	want := map[string]string{
		"_type":          "credential",
		"_proto":         "ldap",
		"username":       "alice",
		"domain":         "CORP",
		"workstation":    "WS01",
		"ntlm_version":   "v2",
		"method":         "NTLMSSP",
		"sasl_mechanism": "GSS-SPNEGO",
		"hashcat_mode":   "5600",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
	wantLine := fmt.Sprintf("alice::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
	if !strings.HasSuffix(rec["_server"], ":0") {
		t.Errorf("_server = %q, want the configured bind address", rec["_server"])
	}
}

// TestLDAPSASLNTLMRaw checks the same exchange with bare NTLMSSP messages,
// which is what ldap3 and other non-SPNEGO clients send, and confirms the
// server answers in the same unwrapped shape.
func TestLDAPSASLNTLMRaw(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("NTLM", ldapTestNegotiate()))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("round one result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	if NTLMMessageType(creds) != NTLMTypeChallenge {
		t.Fatalf("serverSaslCreds is not a bare CHALLENGE: %x", creds)
	}

	blob := ntlmTestV2Blob(ntlmSecBuf(creds, 40), false)
	proof := ntlmTestV2Proof("Hunter2", "bob", "CORP", NTLMConf.Challenge[:], blob)
	auth := ntlmTestAuthMsg("bob", "CORP", "LAPTOP", nil, append(proof, blob...), nil, 0)

	code, _ = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("NTLM", auth))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("round two result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}

	rec := ldapTestWaitCred(t, got)
	if rec["username"] != "bob" || rec["domain"] != "CORP" || rec["workstation"] != "LAPTOP" {
		t.Errorf("identity = %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}
	if rec["sasl_mechanism"] != "NTLM" || rec["method"] != "NTLMSSP" {
		t.Errorf("method = %q, sasl_mechanism = %q", rec["method"], rec["sasl_mechanism"])
	}
	if rec["hashcat_mode"] != "5600" {
		t.Errorf("hashcat_mode = %q, want 5600", rec["hashcat_mode"])
	}
}

// TestLDAPSASLNTLMv1 checks that a NetNTLMv1 response is recorded as mode
// 5500 over LDAP as well.
func TestLDAPSASLNTLMv1(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	if code, _ := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("NTLM", ldapTestNegotiate())); code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("round one result code %d", code)
	}

	nt := ntlmTestV1Response("Password1", NTLMConf.Challenge[:])
	lm := make([]byte, 24)
	auth := ntlmTestAuthMsg("carol", "CORP", "OLDBOX", lm, nt, nil, 0)
	if code, _ := ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("NTLM", auth)); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("round two result code %d", code)
	}

	rec := ldapTestWaitCred(t, got)
	if rec["ntlm_version"] != "v1" || rec["hashcat_mode"] != "5500" {
		t.Errorf("ntlm_version = %q, hashcat_mode = %q", rec["ntlm_version"], rec["hashcat_mode"])
	}
	wantLine := fmt.Sprintf("carol::OLDBOX:%s:%s:%s", hex.EncodeToString(lm),
		hex.EncodeToString(nt), hex.EncodeToString(NTLMConf.Challenge[:]))
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
}

// TestLDAPSASLSPNEGOWithoutNTLM checks that a client opening with a token
// carrying no NTLMSSP message is asked to try again with NTLMSSP rather than
// being refused.
func TestLDAPSASLSPNEGOWithoutNTLM(t *testing.T) {
	addr, _ := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	// A negTokenInit offering only the Kerberos mechanism.
	kerberos := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	mechTypes := smbDER(0x30, smbDER(0x06, kerberos))
	token := smbDER(0x60, append(smbDER(0x06, smbOIDSPNEGO),
		smbDER(0xa0, smbDER(0x30, smbDER(0xa0, mechTypes)))...))

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("GSS-SPNEGO", token))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	if !bytes.Contains(creds, smbMechNTLMSSP) {
		t.Errorf("serverSaslCreds does not select NTLMSSP: %x", creds)
	}
	if FindNTLMSSP(creds) != nil {
		t.Errorf("serverSaslCreds should carry no response token: %x", creds)
	}

	// The client can now start NTLM on the same connection.
	code, creds = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("GSS-SPNEGO", ldapTestNegotiate()))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("follow-up result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	if NTLMMessageType(creds) != NTLMTypeChallenge {
		t.Errorf("follow-up serverSaslCreds carries no CHALLENGE: %x", creds)
	}
}

// TestLDAPSASLGSSAPIKerberos checks that a raw GSSAPI bind, which is
// Kerberos, is refused as an unsupported mechanism rather than answered with
// a SPNEGO token the client never asked for.
func TestLDAPSASLGSSAPIKerberos(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	kerberos := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
	token := smbDER(0x60, append(smbDER(0x06, kerberos), 0x01, 0x00, 0x6e, 0x01))

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("GSSAPI", token))
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("result code %d, want %d", code, ldap.LDAPResultAuthMethodNotSupported)
	}
	if creds != nil {
		t.Errorf("response carries serverSaslCreds %x", creds)
	}
	select {
	case rec := <-got:
		t.Errorf("Kerberos bind recorded a credential: %v", rec)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestLDAPSSASLNTLM runs the NTLM bind over TLS and checks that the capture is
// recorded under the ldaps protocol name.
func TestLDAPSSASLNTLM(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 4)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	certPEM, keyPEM := imapTestCert(t)
	conf := NewConfLDAP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.TLS = true
	conf.TLSName = "localhost"
	conf.TLSCert = certPEM
	conf.TLSKey = keyPEM

	if err := SpawnLDAP(conf); err != nil {
		t.Fatalf("SpawnLDAP failed: %s", err)
	}
	t.Cleanup(func() {
		conf.Shutdown()
		rw.Done()
	})

	conn, err := tls.Dial("tcp", conf.listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("GSS-SPNEGO", smbSPNEGONegTokenResp(ldapTestNegotiate())))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("round one result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	challenge := FindNTLMSSP(creds)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("serverSaslCreds carries no CHALLENGE: %x", creds)
	}

	blob := ntlmTestV2Blob(ntlmSecBuf(challenge, 40), false)
	proof := ntlmTestV2Proof("Password1", "alice", "CORP", NTLMConf.Challenge[:], blob)
	auth := ntlmTestAuthMsg("alice", "CORP", "WS01", nil, append(proof, blob...), nil, 0)

	code, _ = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("GSS-SPNEGO", smbSPNEGONegTokenResp(auth)))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("round two result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}

	rec := ldapTestWaitCred(t, got)
	if rec["_proto"] != "ldaps" {
		t.Errorf("_proto = %q, want ldaps", rec["_proto"])
	}
	if rec["username"] != "alice" || rec["hashcat_mode"] != "5600" {
		t.Errorf("username = %q, hashcat_mode = %q", rec["username"], rec["hashcat_mode"])
	}
}

// TestLDAPSASLPlain checks the cleartext SASL PLAIN capture.
func TestLDAPSASLPlain(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("PLAIN", []byte("\x00alice@corp.local\x00S3cr3t!")))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}
	if creds != nil {
		t.Errorf("PLAIN bind response carries serverSaslCreds %x", creds)
	}

	rec := ldapTestWaitCred(t, got)
	want := map[string]string{
		"_proto":         "ldap",
		"username":       "alice@corp.local",
		"password":       "S3cr3t!",
		"method":         "SASL PLAIN",
		"sasl_mechanism": "PLAIN",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
	if _, ok := rec["authzid"]; ok {
		t.Errorf("record gained an authzid field: %q", rec["authzid"])
	}
}

// TestLDAPSASLPlainAuthzid checks that a distinct authorization identity is
// recorded alongside the account that authenticated.
func TestLDAPSASLPlainAuthzid(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("plain", []byte("admin\x00svc_backup\x00p@ss")))

	rec := ldapTestWaitCred(t, got)
	if rec["username"] != "svc_backup" || rec["password"] != "p@ss" || rec["authzid"] != "admin" {
		t.Errorf("record = %q/%q/%q", rec["username"], rec["password"], rec["authzid"])
	}
}

// TestLDAPSASLPlainNoInitialResponse checks that a client that waits to be
// asked gets an empty challenge rather than an error.
func TestLDAPSASLPlainNoInitialResponse(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("PLAIN", nil))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	if creds != nil {
		t.Errorf("empty PLAIN challenge carries %x", creds)
	}

	code, _ = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("PLAIN", []byte("\x00dave\x00pw")))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("second result code %d", code)
	}
	if rec := ldapTestWaitCred(t, got); rec["username"] != "dave" {
		t.Errorf("username = %q", rec["username"])
	}
}

// TestLDAPSASLDigestMD5 runs the DIGEST-MD5 challenge/response exchange and
// checks the recorded digest line.
func TestLDAPSASLDigestMD5(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("DIGEST-MD5", nil))
	if code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("round one result code %d, want %d", code, ldap.LDAPResultSaslBindInProgress)
	}
	challenge := ldapDigestParams(string(creds))
	if challenge["nonce"] == "" || challenge["qop"] != "auth" || challenge["algorithm"] != "md5-sess" {
		t.Fatalf("challenge = %q", creds)
	}

	response := fmt.Sprintf(`username="alice",realm="%s",nonce="%s",cnonce="OA6MHXh6VqTrRk",nc=00000001,`+
		`qop=auth,digest-uri="ldap/dc01.corp.local",response=d388dad90d4bbd760a152321f2143af7,charset=utf-8`,
		challenge["realm"], challenge["nonce"])

	code, _ = ldapTestBind(t, conn, 2, "", ldapTestSASLAuth("DIGEST-MD5", []byte(response)))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("round two result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}

	rec := ldapTestWaitCred(t, got)
	wantLine := fmt.Sprintf("alice:$sasl$DIGEST-MD5$%s$%s$OA6MHXh6VqTrRk$00000001$auth$ldap/dc01.corp.local$d388dad90d4bbd760a152321f2143af7",
		challenge["realm"], challenge["nonce"])
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
	if rec["username"] != "alice" || rec["method"] != "SASL DIGEST-MD5" {
		t.Errorf("username = %q, method = %q", rec["username"], rec["method"])
	}
	if rec["domain"] != challenge["realm"] {
		t.Errorf("domain = %q, want %q", rec["domain"], challenge["realm"])
	}
}

// TestLDAPSASLUnknownMechanism checks that an unsupported mechanism is
// refused without recording anything.
func TestLDAPSASLUnknownMechanism(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	code, _ := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("SCRAM-SHA-256", []byte("n,,n=alice,r=abc")))
	if code != ldap.LDAPResultAuthMethodNotSupported {
		t.Errorf("result code %d, want %d", code, ldap.LDAPResultAuthMethodNotSupported)
	}
	select {
	case rec := <-got:
		t.Errorf("unsupported mechanism recorded a credential: %v", rec)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestLDAPMalformedBinds checks that truncated and nonsensical bind requests
// are answered with an error instead of panicking, hanging or recording a
// credential, and that the connection still works afterwards.
func TestLDAPMalformedBinds(t *testing.T) {
	tests := []struct {
		name string
		auth *ber.Packet
		// children replaces the whole bind request body when non-nil.
		children []*ber.Packet
	}{
		{
			name: "sasl with no mechanism",
			auth: ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.LDAPBindAuthSASL, nil, "sasl"),
		},
		{
			name: "sasl mechanism is not a string",
			auth: func() *ber.Packet {
				p := ber.Encode(ber.ClassContext, ber.TypeConstructed, ldap.LDAPBindAuthSASL, nil, "sasl")
				p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 7, "mechanism"))
				return p
			}(),
		},
		{
			name: "sasl primitive instead of a sequence",
			auth: ber.NewString(ber.ClassContext, ber.TypePrimitive, ldap.LDAPBindAuthSASL, "GSS-SPNEGO", "sasl"),
		},
		{
			name: "unknown authentication choice",
			auth: ber.NewString(ber.ClassContext, ber.TypePrimitive, 9, "whatever", "auth"),
		},
		{
			name: "truncated bind request",
			children: []*ber.Packet{
				ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"),
			},
		},
		{
			name: "version is not an integer",
			children: []*ber.Packet{
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "three", "Version"),
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"),
				ldapTestSimpleAuth("pw"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := ldapTestServer(t)
			conn := ldapTestDial(t, addr)

			req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind Request")
			if tc.children != nil {
				for _, child := range tc.children {
					req.AppendChild(child)
				}
			} else {
				req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
				req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))
				req.AppendChild(tc.auth)
			}
			pkt := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
			pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Message ID"))
			pkt.AppendChild(req)

			if _, err := conn.Write(pkt.Bytes()); err != nil {
				t.Fatalf("write: %s", err)
			}

			// Either answer is acceptable: a failure result code, or a
			// closed connection for a request the server could not read
			// at all. What must not happen is a success, a credential,
			// or a hang.
			_, code, creds, err := ldapTestBindResponse(conn)
			if err == nil {
				if code == ldap.LDAPResultSuccess || code == ldap.LDAPResultSaslBindInProgress {
					t.Errorf("result code %d, want a failure", code)
				}
				if creds != nil {
					t.Errorf("response carries serverSaslCreds %x", creds)
				}
			}
			select {
			case rec := <-got:
				t.Errorf("malformed bind recorded a credential: %v", rec)
			default:
			}

			// The listener is still serving: a good bind is captured as
			// usual on a fresh connection.
			next := ldapTestDial(t, addr)
			if code, _ := ldapTestBind(t, next, 2, "cn=ok", ldapTestSimpleAuth("pw")); code != ldap.LDAPResultInvalidCredentials {
				t.Errorf("follow-up bind result code %d", code)
			}
			if rec := ldapTestWaitCred(t, got); rec["username"] != "cn=ok" {
				t.Errorf("follow-up username = %q", rec["username"])
			}
		})
	}
}

// TestLDAPTruncatedStream checks that a bind request cut off mid-packet closes
// the connection without recording anything or hanging the listener.
func TestLDAPTruncatedStream(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	auth := ldapTestSASLAuth("GSS-SPNEGO", ldapTestNegotiate())
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "Bind Request")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))
	req.AppendChild(auth)
	pkt := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Message ID"))
	pkt.AppendChild(req)

	full := pkt.Bytes()
	if _, err := conn.Write(full[:len(full)/2]); err != nil {
		t.Fatalf("write: %s", err)
	}
	conn.Close()

	select {
	case rec := <-got:
		t.Errorf("truncated bind recorded a credential: %v", rec)
	case <-time.After(250 * time.Millisecond):
	}

	// A fresh connection is still served.
	next := ldapTestDial(t, addr)
	if code, _ := ldapTestBind(t, next, 1, "cn=bob", ldapTestSimpleAuth("pw")); code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("result code %d after a truncated connection", code)
	}
	if rec := ldapTestWaitCred(t, got); rec["username"] != "cn=bob" {
		t.Errorf("username = %q", rec["username"])
	}
}

// TestLDAPSASLOversizedCredential checks that an outsized SASL blob is
// refused rather than parsed.
func TestLDAPSASLOversizedCredential(t *testing.T) {
	addr, got := ldapTestServer(t)
	conn := ldapTestDial(t, addr)

	// Larger than ldapSASLMaxCreds but inside what the BER reader accepts.
	huge := bytes.Repeat([]byte("A"), ldapSASLMaxCreds+1)
	code, creds := ldapTestBind(t, conn, 1, "", ldapTestSASLAuth("PLAIN", huge))
	if code != ldap.LDAPResultInvalidCredentials {
		t.Errorf("result code %d, want %d", code, ldap.LDAPResultInvalidCredentials)
	}
	if creds != nil {
		t.Errorf("response carries serverSaslCreds %x", creds)
	}
	select {
	case rec := <-got:
		t.Errorf("oversized credential recorded: %v", rec)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestLDAPDigestParams checks the DIGEST-MD5 directive parser against quoting,
// escapes and malformed input.
func TestLDAPDigestParams(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "quoted and bare values",
			in:   `username="alice",realm="corp",nc=00000001,qop=auth`,
			want: map[string]string{"username": "alice", "realm": "corp", "nc": "00000001", "qop": "auth"},
		},
		{
			name: "comma inside a quoted value",
			in:   `realm="corp,local",nonce="abc"`,
			want: map[string]string{"realm": "corp,local", "nonce": "abc"},
		},
		{
			name: "escaped quote",
			in:   `realm="a\"b",nonce=c`,
			want: map[string]string{"realm": `a"b`, "nonce": "c"},
		},
		{
			name: "keys are lowercased",
			in:   `Username="alice",NONCE=xyz`,
			want: map[string]string{"username": "alice", "nonce": "xyz"},
		},
		{
			name: "unterminated quote",
			in:   `realm="corp`,
			want: map[string]string{"realm": "corp"},
		},
		{
			name: "trailing key with no value",
			in:   `realm=corp,nonce`,
			want: map[string]string{"realm": "corp"},
		},
		{
			name: "empty",
			in:   "",
			want: map[string]string{},
		},
		{
			name: "separators only",
			in:   ",,, ,,",
			want: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ldapDigestParams(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
