package ldap

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"

	ber "github.com/atredispartners/flamingo/pkg/asn1-ber"
)

// SASL bind coverage for the flamingo SASLBinder change. The client half of
// this package only speaks simple binds, so these tests encode the SASL bind
// themselves and read the serverSaslCreds back out of the response.

// saslBind sends a SASL bind request and returns the result code and the
// serverSaslCreds from the response. A nil credentials argument leaves the
// optional credentials element out entirely, which is what a client sends when
// a mechanism has no initial response.
func saslBind(l *Conn, bindDN, mechanism string, credentials []byte) (LDAPResultCode, []byte, error) {
	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, LDAPBindAuthSASL, nil, "SASL Credentials")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "Mechanism"))
	if credentials != nil {
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(credentials), "Credentials"))
	}
	return saslBindAuth(l, bindDN, auth)
}

// saslBindAuth sends a bind request whose authentication choice is auth, so a
// test can hand the server a malformed SaslCredentials.
func saslBindAuth(l *Conn, bindDN string, auth *ber.Packet) (LDAPResultCode, []byte, error) {
	messageID := l.nextMessageID()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, bindDN, "User Name"))
	bindRequest.AppendChild(auth)
	packet.AppendChild(bindRequest)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return 0, nil, err
	}
	defer l.finishMessage(messageID)

	response := <-channel
	if response == nil {
		return 0, nil, errors.New("ldap: could not retrieve response")
	}
	return parseBindResponse(response)
}

// parseBindResponse pulls the result code and the optional [7] serverSaslCreds
// out of a bind response. getLDAPResultCode cannot be used here: it insists on
// exactly three children, and a SASL response that carries serverSaslCreds has
// four.
func parseBindResponse(packet *ber.Packet) (LDAPResultCode, []byte, error) {
	if len(packet.Children) < 2 {
		return 0, nil, errors.New("ldap: malformed response")
	}
	response := packet.Children[1]
	if response.Tag != ApplicationBindResponse || len(response.Children) < 3 {
		return 0, nil, errors.New("ldap: not a bind response")
	}
	code, ok := response.Children[0].Value.(uint64)
	if !ok {
		return 0, nil, errors.New("ldap: malformed result code")
	}

	var creds []byte
	for _, child := range response.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 7 {
			creds = child.Data.Bytes()
		}
	}
	return LDAPResultCode(code), creds, nil
}

// saslCall is one BindSASL the recorder was given.
type saslCall struct {
	dn          string
	mechanism   string
	credentials []byte
}

// saslRecorder is a Binder that also implements SASLBinder. It answers the
// first request of a connection with a challenge and the next with whatever
// the test asked for, which is the shape of the NTLM exchange flamingo's LDAP
// listener captures.
type saslRecorder struct {
	challenge []byte
	final     LDAPResultCode
	err       error
	panics    bool

	mu       sync.Mutex
	recorded []saslCall
}

func (b *saslRecorder) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	return LDAPResultInvalidCredentials, nil
}

func (b *saslRecorder) BindSASL(bindDN, mechanism string, credentials []byte, conn net.Conn) (LDAPResultCode, []byte, error) {
	b.mu.Lock()
	// append of nothing onto a nil slice stays nil, so an omitted
	// credentials element is still distinguishable from an empty one.
	b.recorded = append(b.recorded, saslCall{dn: bindDN, mechanism: mechanism, credentials: append([]byte(nil), credentials...)})
	n := len(b.recorded)
	b.mu.Unlock()

	if b.panics {
		panic("test panic in a SASL bind handler")
	}
	if b.err != nil {
		return 0, nil, b.err
	}
	if n == 1 {
		return LDAPResultSaslBindInProgress, b.challenge, nil
	}
	return b.final, nil, nil
}

func (b *saslRecorder) calls() []saslCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]saslCall(nil), b.recorded...)
}

// testSASLServer starts a server whose bind handler is binder.
func testSASLServer(t *testing.T, binder Binder) *Conn {
	t.Helper()

	s := NewServer()
	s.BindFunc("", binder)
	return dialTest(t, testServer(t, s))
}

// ///////////////////////
// TestBindSASLExchange drives a two round trip SASL bind: the handler
// challenges the first request and accepts the second, and the challenge has
// to reach the client as serverSaslCreds.
func TestBindSASLExchange(t *testing.T) {
	// A truncated NTLMSSP CHALLENGE: not valid UTF-8, so it also shows the
	// credentials surviving as bytes rather than as a string.
	challenge := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0xff, 0xfe}
	negotiate := []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x80}

	binder := &saslRecorder{challenge: challenge, final: LDAPResultInvalidCredentials}
	l := testSASLServer(t, binder)

	code, creds, err := saslBind(l, "", "GSS-SPNEGO", negotiate)
	if err != nil {
		t.Fatalf("first SASL bind failed: %s", err)
	}
	if code != LDAPResultSaslBindInProgress {
		t.Errorf("first SASL bind returned %d, want sasl bind in progress", code)
	}
	if !bytes.Equal(creds, challenge) {
		t.Errorf("serverSaslCreds is %x, want %x", creds, challenge)
	}

	code, creds, err = saslBind(l, "", "GSS-SPNEGO", []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03})
	if err != nil {
		t.Fatalf("second SASL bind failed: %s", err)
	}
	if code != LDAPResultInvalidCredentials {
		t.Errorf("second SASL bind returned %d, want invalid credentials", code)
	}
	if len(creds) != 0 {
		t.Errorf("second SASL bind returned serverSaslCreds %x, want none", creds)
	}

	calls := binder.calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 SASL binds to reach the handler, got %d", len(calls))
	}
	if calls[0].mechanism != "GSS-SPNEGO" {
		t.Errorf("handler saw mechanism %q, want GSS-SPNEGO", calls[0].mechanism)
	}
	if !bytes.Equal(calls[0].credentials, negotiate) {
		t.Errorf("handler saw credentials %x, want %x", calls[0].credentials, negotiate)
	}
}

// ///////////////////////
// TestBindSASLRouting checks a SASL bind reaches the handler registered for
// the bind DN's base, the same way a simple bind does.
func TestBindSASLRouting(t *testing.T) {
	def := &saslRecorder{final: LDAPResultSuccess}
	scoped := &saslRecorder{final: LDAPResultSuccess}

	s := NewServer()
	s.BindFunc("", def)
	s.BindFunc("c=testz", scoped)
	l := dialTest(t, testServer(t, s))

	if _, _, err := saslBind(l, "cn=testy,o=testers,c=testz", "PLAIN", []byte("\x00testy\x00secret")); err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if len(def.calls()) != 0 {
		t.Errorf("the default handler saw a bind for c=testz")
	}
	if calls := scoped.calls(); len(calls) != 1 {
		t.Errorf("expected 1 bind on the c=testz handler, got %d", len(calls))
	}
}

// ///////////////////////
// TestBindSASLNoCredentials covers a mechanism with no initial response: the
// optional credentials element is absent and the handler must be told so.
func TestBindSASLNoCredentials(t *testing.T) {
	binder := &saslRecorder{final: LDAPResultSuccess}
	l := testSASLServer(t, binder)

	code, _, err := saslBind(l, "", "NTLM", nil)
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultSaslBindInProgress {
		t.Errorf("SASL bind returned %d, want sasl bind in progress", code)
	}

	calls := binder.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 SASL bind to reach the handler, got %d", len(calls))
	}
	if calls[0].credentials != nil {
		t.Errorf("handler saw credentials %x, want none", calls[0].credentials)
	}
}

// ///////////////////////
// TestBindSASLEmptyCredentials covers a zero-length credentials element, which
// the BER decoder used to reject along with the whole bind request.
func TestBindSASLEmptyCredentials(t *testing.T) {
	binder := &saslRecorder{final: LDAPResultSuccess}
	l := testSASLServer(t, binder)

	code, _, err := saslBind(l, "", "NTLM", []byte{})
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultSaslBindInProgress {
		t.Errorf("SASL bind returned %d, want sasl bind in progress", code)
	}

	calls := binder.calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 SASL bind to reach the handler, got %d", len(calls))
	}
	if len(calls[0].credentials) != 0 {
		t.Errorf("handler saw credentials %x, want none", calls[0].credentials)
	}
}

// ///////////////////////
// TestBindSASLUnsupported checks the pre-flamingo behaviour is unchanged for a
// Binder that does not implement SASLBinder.
func TestBindSASLUnsupported(t *testing.T) {
	l := testSASLServer(t, bindAnonOK{})

	code, _, err := saslBind(l, "", "GSS-SPNEGO", []byte("token"))
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultInappropriateAuthentication {
		t.Errorf("SASL bind against a plain Binder returned %d, want inappropriate authentication", code)
	}
}

// ///////////////////////
// TestBindSASLEmptyCredentialsSequence hands the server a SaslCredentials with
// no mechanism in it, which has no handler to route to.
func TestBindSASLEmptyCredentialsSequence(t *testing.T) {
	binder := &saslRecorder{final: LDAPResultSuccess}
	l := testSASLServer(t, binder)

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, LDAPBindAuthSASL, nil, "SASL Credentials")
	code, _, err := saslBindAuth(l, "", auth)
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultInappropriateAuthentication {
		t.Errorf("SASL bind with no mechanism returned %d, want inappropriate authentication", code)
	}
	if calls := binder.calls(); len(calls) != 0 {
		t.Errorf("a bind with no mechanism reached the handler: %+v", calls)
	}
}

// ///////////////////////
func TestBindSASLHandlerError(t *testing.T) {
	binder := &saslRecorder{err: errors.New("handler exploded")}
	l := testSASLServer(t, binder)

	code, _, err := saslBind(l, "", "PLAIN", []byte("token"))
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultOperationsError {
		t.Errorf("SASL bind returned %d after a handler error, want operations error", code)
	}
}

// ///////////////////////
func TestBindSASLPanic(t *testing.T) {
	binder := &saslRecorder{panics: true}
	l := testSASLServer(t, binder)

	code, creds, err := saslBind(l, "", "PLAIN", []byte("token"))
	if err != nil {
		t.Fatalf("SASL bind failed: %s", err)
	}
	if code != LDAPResultOperationsError {
		t.Errorf("SASL bind returned %d after a handler panic, want operations error", code)
	}
	if len(creds) != 0 {
		t.Errorf("SASL bind returned serverSaslCreds %x after a panic, want none", creds)
	}
}
