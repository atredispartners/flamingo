package flamingo

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mandiant/gopacket/pkg/relay"
)

// The adapter tests drive NTLMCapture through a stand-in ProtocolServer so the
// rendezvous can be stepped one channel at a time. The listeners on top of it
// are exercised over real sockets in msrpc_test.go, winrm_test.go and
// adws_test.go.

// captureTestServer is a relay.ProtocolServer that pushes AuthResults on
// demand instead of accepting connections.
type captureTestServer struct {
	results  chan<- relay.AuthResult
	startErr error
	stopped  chan struct{}
}

func newCaptureTestServer() *captureTestServer {
	return &captureTestServer{stopped: make(chan struct{}, 4)}
}

func (s *captureTestServer) Start(results chan<- relay.AuthResult) error {
	if s.startErr != nil {
		return s.startErr
	}
	s.results = results
	return nil
}

func (s *captureTestServer) Stop() error {
	s.stopped <- struct{}{}
	return nil
}

// push hands the adapter a new exchange and returns it, the way an upstream
// connection handler would.
func (s *captureTestServer) push(type1 []byte, conn net.Conn) relay.AuthResult {
	a := relay.AuthResult{
		NTLMType1:  type1,
		SourceAddr: "198.51.100.7:51515",
		ServerConn: conn,
		Type2Ch:    make(chan []byte, 1),
		Type3Ch:    make(chan []byte, 1),
		ResultCh:   make(chan bool, 1),
	}
	s.results <- a
	return a
}

// captureTestWriter returns a record writer whose records land on a channel.
func captureTestWriter(t *testing.T) (*RecordWriter, chan map[string]string) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})
	t.Cleanup(rw.Done)
	return rw, got
}

// captureTestStart builds an adapter over a stand-in server and starts it.
func captureTestStart(t *testing.T, timeout time.Duration) (*NTLMCapture, *captureTestServer, chan map[string]string) {
	t.Helper()
	rw, got := captureTestWriter(t)
	c := NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	c.Timeout = timeout
	srv := newCaptureTestServer()
	if err := c.Start(srv); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	t.Cleanup(func() { c.Stop() })
	return c, srv, got
}

// captureTestPort reserves a free localhost port. The listeners in this phase
// are bound by upstream, which keeps its net.Listener unexported, so a test
// has to choose the port rather than read it back.
func captureTestPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot reserve a port: %s", err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return port
}

// captureTestNegotiate is a minimal NTLMSSP NEGOTIATE message.
func captureTestNegotiate() []byte {
	m := make([]byte, 40)
	copy(m, ntlmSignature)
	binary.LittleEndian.PutUint32(m[8:], NTLMTypeNegotiate)
	binary.LittleEndian.PutUint32(m[12:], NTLMFlagUnicode|NTLMFlagNTLM|NTLMFlagRequestTarget|
		NTLMFlagExtendedSessionSecurity|NTLMFlagVersion|NTLMFlagAlwaysSign)
	copy(m[32:40], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})
	return m
}

// captureTestV2Auth builds a genuine NetNTLMv2 AUTHENTICATE answering the
// given CHALLENGE, so the recorded hashcat line can be checked against a
// response that was really computed over flamingo's challenge.
func captureTestV2Auth(t *testing.T, challenge []byte, user, domain, ws, password string) (msg, proof, blob []byte) {
	t.Helper()
	info := ntlmSecBuf(challenge, 40)
	if len(info) == 0 {
		t.Fatal("CHALLENGE carries no target info")
	}
	blob = ntlmTestV2Blob(info, false)
	proof = ntlmTestV2Proof(password, user, domain, NTLMConf.Challenge[:], blob)
	nt := append(append([]byte(nil), proof...), blob...)
	msg = ntlmTestAuthMsg(user, domain, ws, nil, nt, nil, NTLMFlagExtendedSessionSecurity)
	return msg, proof, blob
}

// captureTestChallenge waits for the adapter's CHALLENGE.
func captureTestChallenge(t *testing.T, a relay.AuthResult) []byte {
	t.Helper()
	select {
	case msg, ok := <-a.Type2Ch:
		if !ok {
			t.Fatal("challenge channel closed instead of carrying a CHALLENGE")
		}
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("no challenge offered")
		return nil
	}
}

// captureTestResult waits for the adapter's verdict.
func captureTestResult(t *testing.T, a relay.AuthResult) bool {
	t.Helper()
	select {
	case ok := <-a.ResultCh:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("no result reported; the victim goroutine would have blocked forever")
		return false
	}
}

// captureTestRecord waits for a captured credential.
// captureTestRecord waits for the next credential. Observations are skipped:
// the HTTP-backed listeners record an access for each un-authenticated step of
// the exchange they are themselves driving, so a credential is not necessarily
// the first record to arrive.
func captureTestRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case rec := <-got:
			if rec["_type"] == "credential" {
				return rec
			}
		case <-deadline:
			t.Fatal("no credential captured")
			return nil
		}
	}
}

// TestNTLMCaptureFixedChallenge is the central guarantee of the adapter: the
// CHALLENGE it answers with carries flamingo's own configured challenge, not
// the random one upstream's pkg/ntlm would generate, and the recorded hashcat
// line is built from that same challenge. A random challenge would produce a
// line nothing could ever crack.
func TestNTLMCaptureFixedChallenge(t *testing.T) {
	_, srv, got := captureTestStart(t, 5*time.Second)

	a := srv.push(captureTestNegotiate(), nil)
	challenge := captureTestChallenge(t, a)

	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("answer is not a CHALLENGE message: %x", challenge)
	}
	if len(challenge) < 32 {
		t.Fatalf("short CHALLENGE: %x", challenge)
	}
	if string(challenge[24:32]) != string(NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, proof, blob := captureTestV2Auth(t, challenge, "nadia", "CORP", "WS01", "Summer2024!")
	a.Type3Ch <- msg

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("nadia::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "5600" {
		t.Errorf("hashcat_mode is %q, want 5600", rec["hashcat_mode"])
	}
	if rec["_proto"] != "msrpc" {
		t.Errorf("_proto is %q, want msrpc", rec["_proto"])
	}
	if rec["_type"] != "credential" {
		t.Errorf("_type is %q, want credential", rec["_type"])
	}
	if rec["_host"] != "198.51.100.7:51515" {
		t.Errorf("_host is %q, want the victim address", rec["_host"])
	}
	if rec["_server"] != "127.0.0.1:135" {
		t.Errorf("_server is %q, want the listen address", rec["_server"])
	}
	if rec["username"] != "nadia" || rec["domain"] != "CORP" || rec["workstation"] != "WS01" {
		t.Errorf("identity fields are %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}
	if rec["ntlm_version"] != "v2" {
		t.Errorf("ntlm_version is %q, want v2", rec["ntlm_version"])
	}

	// Capture only: the victim is always told the logon failed.
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
}

// TestNTLMCaptureNTLMv1 covers the other hashcat layout.
func TestNTLMCaptureNTLMv1(t *testing.T) {
	_, srv, got := captureTestStart(t, 5*time.Second)

	a := srv.push(captureTestNegotiate(), nil)
	captureTestChallenge(t, a)

	nt := ntlmTestV1Response("Password1", NTLMConf.Challenge[:])
	a.Type3Ch <- ntlmTestAuthMsg("legacy", "CORP", "OLDBOX", make([]byte, 24), nt, nil, 0)

	rec := captureTestRecord(t, got)
	if rec["hashcat_mode"] != "5500" {
		t.Errorf("hashcat_mode is %q, want 5500", rec["hashcat_mode"])
	}
	if rec["ntlm_version"] != "v1" {
		t.Errorf("ntlm_version is %q, want v1", rec["ntlm_version"])
	}
	// Mode 5500 names the workstation, not the domain, and ends with the
	// server challenge.
	if !strings.HasPrefix(rec["hashcat"], "legacy::OLDBOX:") {
		t.Errorf("hashcat line is %q", rec["hashcat"])
	}
	if !strings.HasSuffix(rec["hashcat"], hex.EncodeToString(NTLMConf.Challenge[:])) {
		t.Errorf("hashcat line does not end with the configured challenge: %q", rec["hashcat"])
	}
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
}

// TestNTLMCaptureSPNEGOWrapped checks that a Type3 arriving inside a SPNEGO
// token is still found, as WinRM's Negotiate scheme can deliver it.
func TestNTLMCaptureSPNEGOWrapped(t *testing.T) {
	_, srv, got := captureTestStart(t, 5*time.Second)

	a := srv.push(captureTestNegotiate(), nil)
	challenge := captureTestChallenge(t, a)
	msg, _, _ := captureTestV2Auth(t, challenge, "wrapped", "CORP", "WS02", "hunter2")
	a.Type3Ch <- smbSPNEGONegTokenResp(msg)

	rec := captureTestRecord(t, got)
	if rec["username"] != "wrapped" {
		t.Errorf("username is %q, want wrapped", rec["username"])
	}
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
}

// captureTestResponder is a stand-in for the relay responder Phase 6 will
// supply: its own challenge, and a successful outcome.
type captureTestResponder struct {
	challenge []byte
	err       error
	success   bool
	seen      chan *NTLMAuth
}

func (r *captureTestResponder) Challenge(_ *NTLMExchange) ([]byte, error) {
	return r.challenge, r.err
}

func (r *captureTestResponder) Authenticate(_ *NTLMExchange, auth *NTLMAuth, _ []byte) bool {
	if r.seen != nil {
		r.seen <- auth
	}
	return r.success
}

// TestNTLMCaptureResponderSeam exercises the seam the relay phase builds on: a
// responder supplies the challenge and the outcome, while the adapter still
// parses and records the credential.
func TestNTLMCaptureResponderSeam(t *testing.T) {
	rw, got := captureTestWriter(t)
	c := NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	c.Timeout = 5 * time.Second
	resp := &captureTestResponder{
		challenge: NTLMChallengeMessage(0),
		success:   true,
		seen:      make(chan *NTLMAuth, 1),
	}
	c.Responder = resp
	srv := newCaptureTestServer()
	if err := c.Start(srv); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	defer c.Stop()

	a := srv.push(captureTestNegotiate(), nil)
	challenge := captureTestChallenge(t, a)
	if string(challenge) != string(resp.challenge) {
		t.Error("the responder's challenge was not the one offered to the victim")
	}

	msg, _, _ := captureTestV2Auth(t, challenge, "relayed", "CORP", "WS03", "letmein")
	a.Type3Ch <- msg

	rec := captureTestRecord(t, got)
	if rec["username"] != "relayed" {
		t.Errorf("username is %q, want relayed", rec["username"])
	}

	select {
	case auth := <-resp.seen:
		if auth.User != "relayed" {
			t.Errorf("responder saw user %q", auth.User)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the responder was never asked for an outcome")
	}

	if !captureTestResult(t, a) {
		t.Error("the responder's success was not reported to the victim")
	}
}

// TestNTLMCaptureChallengeError checks the early-return path that matters
// most: when no challenge can be produced the victim's goroutine is parked on
// Type2Ch, and only closing that channel releases it.
func TestNTLMCaptureChallengeError(t *testing.T) {
	rw, _ := captureTestWriter(t)
	c := NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	c.Responder = &captureTestResponder{err: errors.New("no target available")}
	srv := newCaptureTestServer()
	if err := c.Start(srv); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	defer c.Stop()

	a := srv.push(captureTestNegotiate(), nil)
	select {
	case _, ok := <-a.Type2Ch:
		if ok {
			t.Fatal("a challenge was offered despite the responder failing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the challenge channel was never closed; the victim goroutine leaked")
	}
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
}

// TestNTLMCaptureMalformedAuthenticate feeds the adapter rubbish where an
// AUTHENTICATE belongs. Nothing may panic, nothing may be recorded, and the
// victim still has to be released.
func TestNTLMCaptureMalformedAuthenticate(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
	}{
		{"empty", []byte{}},
		{"not ntlmssp", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"truncated", append([]byte(nil), ntlmSignature...)},
		{"wrong type", captureTestNegotiate()},
		{"lying security buffers", func() []byte {
			m := make([]byte, 64)
			copy(m, ntlmSignature)
			binary.LittleEndian.PutUint32(m[8:], NTLMTypeAuthenticate)
			for _, off := range []int{12, 20, 28, 36, 44, 52} {
				binary.LittleEndian.PutUint16(m[off:], 0xffff)
				binary.LittleEndian.PutUint32(m[off+4:], 0xfffffff0)
			}
			return m
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, srv, got := captureTestStart(t, 5*time.Second)
			a := srv.push(captureTestNegotiate(), nil)
			captureTestChallenge(t, a)
			a.Type3Ch <- tc.msg

			if captureTestResult(t, a) {
				t.Error("the victim was told the logon succeeded")
			}
			select {
			case rec := <-got:
				if rec["hashcat"] != "" {
					t.Errorf("malformed input produced a hashcat line: %q", rec["hashcat"])
				}
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// TestNTLMCaptureMalformedNegotiate checks that a nonsense NEGOTIATE still
// gets a usable challenge rather than panicking.
func TestNTLMCaptureMalformedNegotiate(t *testing.T) {
	for _, type1 := range [][]byte{nil, {}, []byte("NTLM"), make([]byte, 13)} {
		_, srv, _ := captureTestStart(t, 100*time.Millisecond)
		a := srv.push(type1, nil)
		challenge := captureTestChallenge(t, a)
		if NTLMMessageType(challenge) != NTLMTypeChallenge {
			t.Fatalf("answer to %x is not a CHALLENGE", type1)
		}
		if captureTestResult(t, a) {
			t.Error("the victim was told the logon succeeded")
		}
	}
}

// TestNTLMCaptureTimeout covers a victim that negotiates and then goes quiet.
// Upstream's handler has no timeout of its own, so the adapter's has to fire,
// release the result channel and close the connection behind it.
func TestNTLMCaptureTimeout(t *testing.T) {
	_, srv, _ := captureTestStart(t, 100*time.Millisecond)

	victim, handler := net.Pipe()
	defer victim.Close()

	a := srv.push(captureTestNegotiate(), handler)
	captureTestChallenge(t, a)

	start := time.Now()
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the timeout took %s to fire", elapsed)
	}

	// The connection is closed so upstream's deadline-less read returns and
	// its goroutine ends.
	victim.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := victim.Read(make([]byte, 1)); err == nil {
		t.Error("the abandoned connection was left open")
	}
}

// TestNTLMCaptureStopReleasesLateVictim covers upstream's lifecycle gap: Stop
// closes the listener but not the connections already accepted, so an exchange
// can still arrive afterwards and has to be released rather than parked.
func TestNTLMCaptureStopReleasesLateVictim(t *testing.T) {
	rw, _ := captureTestWriter(t)
	c := NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	srv := newCaptureTestServer()
	if err := c.Start(srv); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	c.Stop()

	a := srv.push(captureTestNegotiate(), nil)
	select {
	case _, ok := <-a.Type2Ch:
		if ok {
			t.Fatal("a challenge was offered after the listener stopped")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a victim arriving after Stop was never released")
	}
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}
}

// TestNTLMCaptureStopIsPrompt checks that stopping does not wait on an
// exchange that is still holding a victim with a long timeout.
func TestNTLMCaptureStopIsPrompt(t *testing.T) {
	c, srv, _ := captureTestStart(t, time.Hour)

	a := srv.push(captureTestNegotiate(), nil)
	captureTestChallenge(t, a)

	start := time.Now()
	if err := c.Stop(); err != nil {
		t.Fatalf("Stop failed: %s", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Stop took %s", elapsed)
	}
	if !c.IsStopped() {
		t.Error("IsStopped is false after Stop")
	}
	select {
	case <-srv.stopped:
	default:
		t.Error("the protocol server was not stopped")
	}

	// The in-flight exchange abandons itself rather than waiting out its
	// hour-long timeout.
	if captureTestResult(t, a) {
		t.Error("the victim was told the logon succeeded")
	}

	// Stopping twice is harmless.
	if err := c.Stop(); err != nil {
		t.Errorf("second Stop failed: %s", err)
	}
}

// TestNTLMCaptureStartGuards covers the lifecycle edges the listener wrappers
// depend on.
func TestNTLMCaptureStartGuards(t *testing.T) {
	rw, _ := captureTestWriter(t)

	c := NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	if err := c.Start(nil); err == nil {
		t.Error("starting without a server succeeded")
	}

	c = NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	if err := c.Start(newCaptureTestServer()); err != nil {
		t.Fatalf("Start failed: %s", err)
	}
	if err := c.Start(newCaptureTestServer()); err == nil {
		t.Error("starting twice succeeded")
	}
	c.Stop()
	if err := c.Start(newCaptureTestServer()); err == nil {
		t.Error("starting after Stop succeeded")
	}

	// A server that fails to bind leaves the adapter stopped, so a later
	// Stop cannot reach a server that never ran.
	c = NewNTLMCapture("msrpc", "127.0.0.1:135", rw)
	failing := newCaptureTestServer()
	failing.startErr = errors.New("address already in use")
	if err := c.Start(failing); err == nil {
		t.Error("a failing bind was reported as success")
	}
	if !c.IsStopped() {
		t.Error("a failed Start left the adapter running")
	}
	if err := c.Stop(); err != nil {
		t.Errorf("Stop after a failed Start: %s", err)
	}
	select {
	case <-failing.stopped:
		t.Error("a server that never started was stopped")
	default:
	}
}

// TestNTLMCaptureNoGoroutineLeak runs a batch of victims that disconnect
// mid-exchange and checks the adapter is not holding a goroutine for each of
// them afterwards. Upstream parks its handlers on Type2Ch and ResultCh with no
// timeout, so a missed release here would leak for the life of the process.
func TestNTLMCaptureNoGoroutineLeak(t *testing.T) {
	c, srv, _ := captureTestStart(t, 200*time.Millisecond)

	settle(t, 0)
	before := runtime.NumGoroutine()

	const victims = 40
	for i := 0; i < victims; i++ {
		var conn net.Conn
		if i%2 == 0 {
			victim, handler := net.Pipe()
			victim.Close()
			conn = handler
		}
		a := srv.push(captureTestNegotiate(), conn)
		switch i % 4 {
		case 0:
			// Walks off before reading the challenge at all.
		case 1:
			captureTestChallenge(t, a)
		case 2:
			captureTestChallenge(t, a)
			a.Type3Ch <- []byte("garbage")
		case 3:
			captureTestChallenge(t, a)
			captureTestResult(t, a)
		}
	}

	c.Stop()
	settle(t, before)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines went from %d to %d across %d abandoned exchanges", before, after, victims)
	}
}

// settle waits for the goroutine count to come back down to want, giving the
// adapter's post-stop drain window time to expire.
func settle(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		runtime.Gosched()
		if runtime.NumGoroutine() <= want+5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
