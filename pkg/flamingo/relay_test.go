package flamingo

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/mandiant/gopacket/pkg/relay"
)

// --- fake relay target ------------------------------------------------------

// relayFakeChallenge is the server challenge a fake target answers with. It is
// deliberately nothing like NTLMConf.Challenge, so a test can tell at a glance
// whether a victim was answered by the target or by flamingo.
var relayFakeChallenge = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}

// relayFakeType2 is a well-formed CHALLENGE message carrying challenge.
func relayFakeType2(challenge []byte) []byte {
	msg := NTLMChallengeMessage(0)
	copy(msg[24:32], challenge)
	return msg
}

// relayFakeClient is a relay.ProtocolClient that answers from memory, so the
// relay path can be exercised without a Windows host on the other end.
type relayFakeClient struct {
	type2    []byte
	initErr  error
	negErr   error
	authErr  error
	keepErr  error
	admin    bool
	negDelay time.Duration

	mu       sync.Mutex
	gotType1 []byte
	gotType3 []byte
	killed   bool
}

func (c *relayFakeClient) InitConnection() error { return c.initErr }

func (c *relayFakeClient) SendNegotiate(type1 []byte) ([]byte, error) {
	c.mu.Lock()
	c.gotType1 = append([]byte(nil), type1...)
	c.mu.Unlock()
	if c.negDelay > 0 {
		time.Sleep(c.negDelay)
	}
	if c.negErr != nil {
		return nil, c.negErr
	}
	if c.type2 != nil {
		return c.type2, nil
	}
	return relayFakeType2(relayFakeChallenge), nil
}

func (c *relayFakeClient) SendAuth(type3 []byte) error {
	c.mu.Lock()
	c.gotType3 = append([]byte(nil), type3...)
	c.mu.Unlock()
	return c.authErr
}

func (c *relayFakeClient) GetSession() interface{} { return c }
func (c *relayFakeClient) KeepAlive() error        { return c.keepErr }
func (c *relayFakeClient) IsAdmin() bool           { return c.admin }

func (c *relayFakeClient) Kill() {
	c.mu.Lock()
	c.killed = true
	c.mu.Unlock()
}

func (c *relayFakeClient) wasKilled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.killed
}

func (c *relayFakeClient) type3() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gotType3
}

// --- record collection ------------------------------------------------------

// relayTestRecords collects every record a listener emits, so a test can wait
// for one type without consuming another.
type relayTestRecords struct {
	mu  sync.Mutex
	all []map[string]string
}

func (r *relayTestRecords) writer() OutputWriter {
	return func(rec map[string]string) error {
		r.mu.Lock()
		r.all = append(r.all, rec)
		r.mu.Unlock()
		return nil
	}
}

func (r *relayTestRecords) find(rtype string) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.all {
		if rec["_type"] == rtype {
			return rec
		}
	}
	return nil
}

func (r *relayTestRecords) count(rtype string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.all {
		if rec["_type"] == rtype {
			n++
		}
	}
	return n
}

// wait blocks until a record of the given type appears, or fails the test.
func (r *relayTestRecords) wait(t *testing.T, rtype string) map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rec := r.find(rtype); rec != nil {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Fatalf("no %q record after 5s, got %v", rtype, r.all)
	return nil
}

// --- harness ----------------------------------------------------------------

// relayTestSMB spawns an SMB listener wired to the given responder, writing
// its records into recs, and returns its address. A nil responder is
// capture-only.
func relayTestSMB(t *testing.T, responder NTLMResponder, recs *relayTestRecords) string {
	t.Helper()
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, recs.writer())

	conf := NewConfSMB()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.Responder = responder

	if err := SpawnSMB(conf); err != nil {
		t.Fatalf("SpawnSMB failed: %s", err)
	}
	t.Cleanup(func() {
		conf.Shutdown()
		rw.Done()
	})
	return conf.listener.Addr().String()
}

// relayTestConfig builds a relay config for targetAddr without the loop check,
// which would otherwise refuse a target on this host — exactly what these
// tests need to stand up.
func relayTestConfig(t *testing.T, recs *relayTestRecords, targets []string, tune func(*RelayOptions), client func(RelayTarget) (relay.ProtocolClient, error)) *RelayConfig {
	t.Helper()
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, recs.writer())
	t.Cleanup(rw.Done)

	o := RelayOptions{Targets: targets, RecordWriter: rw, Timeout: time.Second}
	if tune != nil {
		tune(&o)
	}
	conf, err := newRelayConfig(o, false)
	if err != nil {
		t.Fatalf("newRelayConfig failed: %s", err)
	}
	if conf == nil {
		t.Fatal("newRelayConfig returned no config for a non-empty target list")
	}
	conf.newClient = client
	return conf
}

// relayTestVictim drives one complete SMB victim exchange against addr and
// returns the CHALLENGE message it was answered with and the status of the
// final SESSION_SETUP.
func relayTestVictim(t *testing.T, addr, user, domain, password string) ([]byte, uint32) {
	t.Helper()
	conn := smbTestDial(t, addr)
	smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB202, wire.SMB210, wire.SMB300, wire.SMB311})

	pkt := smbTestSessionSetup(t, conn, 1, smbSPNEGONegTokenResp(smbTestNegotiateToken()))
	challenge := smbTestChallengeFrom(t, pkt)

	blob := ntlmTestV2Blob(smbTestTargetInfo(t, challenge), false)
	proof := ntlmTestV2Proof(password, user, domain, NTLMServerChallenge(challenge), blob)
	type3 := ntlmTestAuthMsg(user, domain, "VICTIM", nil, append(proof, blob...), nil, 0)

	pkt = smbTestSessionSetup(t, conn, 2, smbSPNEGONegTokenResp(type3))
	return challenge, wire.PacketCodec(pkt).Status()
}

// --- target parsing ---------------------------------------------------------

func TestParseRelayTarget(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bare host is smb", "dc01.corp.local", "smb://dc01.corp.local:445"},
		{"bare host and port is smb", "dc01.corp.local:4445", "smb://dc01.corp.local:4445"},
		{"bare ipv4", "10.0.0.5", "smb://10.0.0.5:445"},
		{"bare ipv4 and port", "10.0.0.5:139", "smb://10.0.0.5:139"},
		{"bare ipv6", "2001:db8::1", "smb://[2001:db8::1]:445"},
		{"bracketed ipv6 and port", "smb://[2001:db8::1]:445", "smb://[2001:db8::1]:445"},
		{"bracketed ipv6 default port", "ldaps://[2001:db8::1]", "ldaps://[2001:db8::1]:636"},
		{"smb", "smb://10.0.0.5", "smb://10.0.0.5:445"},
		{"smb explicit port", "smb://10.0.0.5:4445", "smb://10.0.0.5:4445"},
		{"ldap", "ldap://dc01", "ldap://dc01:389"},
		{"ldaps", "ldaps://dc01", "ldaps://dc01:636"},
		{"http", "http://web01", "http://web01:80"},
		{"https", "https://web01", "https://web01:443"},
		{"mssql", "mssql://sql01", "mssql://sql01:1433"},
		{"winrm", "winrm://srv01", "winrm://srv01:5985"},
		{"winrms", "winrms://srv01", "winrms://srv01:5986"},
		{"rpc", "rpc://srv01", "rpc://srv01:135"},
		{"scheme case is ignored", "SMB://10.0.0.5", "smb://10.0.0.5:445"},
		{"surrounding space is trimmed", "  smb://10.0.0.5  ", "smb://10.0.0.5:445"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRelayTarget(tc.raw)
			if err != nil {
				t.Fatalf("ParseRelayTarget(%q) failed: %s", tc.raw, err)
			}
			if got.String() != tc.want {
				t.Fatalf("ParseRelayTarget(%q) = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}

	// Every scheme the parser advertises must also build a client, or a
	// target would pass configuration and fail at the first victim.
	for _, scheme := range RelaySchemes() {
		target, err := ParseRelayTarget(scheme + "://host01")
		if err != nil {
			t.Fatalf("scheme %q does not parse: %s", scheme, err)
		}
		client, err := target.client()
		if err != nil || client == nil {
			t.Fatalf("scheme %q has no relay client: %v", scheme, err)
		}
	}
}

func TestParseRelayTargetMalformed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"unsupported scheme", "ftp://host01"},
		{"empty scheme", "://host01"},
		{"no host", "smb://"},
		{"no host with port", "smb://:445"},
		{"port zero", "smb://host01:0"},
		{"port too large", "smb://host01:70000"},
		{"port is not a number", "smb://host01:ldap"},
		{"negative port", "smb://host01:-1"},
		{"unterminated ipv6", "smb://[2001:db8::1"},
		{"not an ipv6 literal", "smb://[not-an-address]:445"},
		{"trailing junk after ipv6", "smb://[2001:db8::1]x"},
		{"path", "https://web01/certsrv/certfnsh.asp"},
		{"query", "http://web01:80?a=b"},
		{"credentials", "smb://user:pass@host01"},
		{"space in host", "smb://host 01"},
		{"host is a url", "smb://http://host01"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRelayTarget(tc.raw)
			if err == nil {
				t.Fatalf("ParseRelayTarget(%q) accepted it as %s, want an error", tc.raw, got)
			}
		})
	}
}

// --- configuration safety ---------------------------------------------------

// TestRelayOffByDefault checks the rule that makes every other rule safe: with
// no targets named there is no relay configuration and no responder, so every
// listener stays capture-only.
func TestRelayOffByDefault(t *testing.T) {
	for _, targets := range [][]string{nil, {}, {""}, {"  "}, {",", " , "}} {
		conf, err := NewRelayConfig(RelayOptions{Targets: targets})
		if err != nil {
			t.Fatalf("NewRelayConfig(%q) failed: %s", targets, err)
		}
		if conf != nil {
			t.Fatalf("NewRelayConfig(%q) returned a config, want relay off", targets)
		}
		if r := NewRelayResponder(conf); r != nil {
			t.Fatalf("NewRelayResponder for %q returned a responder, want nil", targets)
		}
	}

	// A nil responder must be a nil interface, not a typed nil: listeners
	// test it for nil to decide whether they are relaying.
	var responder NTLMResponder = NewRelayResponder(nil)
	if responder != nil {
		t.Fatal("NewRelayResponder(nil) is not a nil interface")
	}
	if b := (*RelayConfig)(nil).Banner(); !strings.Contains(b, "OFF") {
		t.Errorf("banner for no relay = %q, want it to say relay is off", b)
	}
}

// TestRelayAttacksNeedTargets checks that naming an attack without a target is
// an error rather than a quiet no-op, since there is no way to enable relaying
// except by naming targets.
func TestRelayAttacksNeedTargets(t *testing.T) {
	_, err := NewRelayConfig(RelayOptions{Attacks: []string{"secretsdump"}})
	if err == nil {
		t.Fatal("attacks without targets were accepted")
	}
}

// TestRelayAttacksAreOptIn checks that targets alone configure no attacks, and
// that an attack is only ever enabled by name.
func TestRelayAttacksAreOptIn(t *testing.T) {
	conf, err := NewRelayConfig(RelayOptions{Targets: []string{"smb://192.0.2.10"}})
	if err != nil {
		t.Fatalf("NewRelayConfig failed: %s", err)
	}
	if len(conf.Attacks) != 0 {
		t.Fatalf("a bare target list configured %d attacks, want none", len(conf.Attacks))
	}
	if !strings.Contains(conf.Banner(), "attacks: none") {
		t.Errorf("banner = %q, want it to say no attacks are configured", conf.Banner())
	}

	named, err := NewRelayConfig(RelayOptions{
		Targets: []string{"smb://192.0.2.10"},
		Attacks: []string{"secretsdump", "samdump,adcs"},
	})
	if err != nil {
		t.Fatalf("NewRelayConfig with attacks failed: %s", err)
	}
	var got []string
	for _, a := range named.Attacks {
		got = append(got, a.Name())
	}
	want := []string{"secretsdump", "samdump", "adcs"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("attacks = %v, want %v", got, want)
	}

	if _, err := NewRelayConfig(RelayOptions{
		Targets: []string{"smb://192.0.2.10"},
		Attacks: []string{"rm -rf"},
	}); err == nil {
		t.Fatal("an unknown attack name was accepted")
	}

	for _, name := range []string{"secretsdump", "samdump", "adcs"} {
		found := false
		for _, known := range RelayAttackNames() {
			if known == name {
				found = true
			}
		}
		if !found {
			t.Errorf("RelayAttackNames does not list %q", name)
		}
	}
}

// TestRelayRefusesLoops checks that a target on this host is refused at
// configuration time. Relaying a victim back into flamingo captures nothing
// new, and against a port flamingo listens on it loops.
func TestRelayRefusesLoops(t *testing.T) {
	addr := relayTestSMB(t, nil, &relayTestRecords{})
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("listener address %q: %s", addr, err)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Flamingo's own listener, by address and by port.
	_, err = NewRelayConfig(RelayOptions{
		Targets:     []string{"smb://" + addr},
		ListenPorts: []uint16{port},
	})
	if err == nil {
		t.Fatal("relaying into flamingo's own listener was accepted")
	}
	if !strings.Contains(err.Error(), "loop") {
		t.Errorf("error = %q, want it to explain the loop", err)
	}

	// A local address on some other port is still this host, and still
	// refused.
	for _, target := range []string{"smb://127.0.0.1", "ldap://127.0.0.1:389", "smb://[::1]:445"} {
		if _, err := NewRelayConfig(RelayOptions{Targets: []string{target}}); err == nil {
			t.Errorf("relaying to %s was accepted, want it refused as this host", target)
		}
	}

	// A target that is not this host is fine, and so is one of several when
	// none of them is local.
	if _, err := NewRelayConfig(RelayOptions{
		Targets:     []string{"smb://192.0.2.10,ldaps://192.0.2.11"},
		ListenPorts: []uint16{445, 389},
	}); err != nil {
		t.Errorf("a remote target was refused: %s", err)
	}

	// One bad target in a list fails the whole configuration.
	if _, err := NewRelayConfig(RelayOptions{
		Targets: []string{"smb://192.0.2.10", "smb://127.0.0.1"},
	}); err == nil {
		t.Error("a list containing a local target was accepted")
	}

	// A target that cannot be resolved is refused rather than deferred: it
	// could not be relayed to anyway, and a name that resolves later could
	// resolve to this host.
	if _, err := NewRelayConfig(RelayOptions{
		Targets: []string{"smb://no-such-host.invalid"},
	}); err == nil {
		t.Error("an unresolvable target was accepted")
	}
}

// --- capture-only behaviour -------------------------------------------------

// TestRelayCaptureOnlyUsesFlamingosChallenge checks that with no relay
// configured the victim is answered with flamingo's fixed challenge, which is
// what keeps a captured hash crackable. This is the assertion that relaying
// genuinely did not happen.
func TestRelayCaptureOnlyUsesFlamingosChallenge(t *testing.T) {
	conf, err := NewRelayConfig(RelayOptions{})
	if err != nil {
		t.Fatalf("NewRelayConfig failed: %s", err)
	}
	recs := &relayTestRecords{}
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	challenge, status := relayTestVictim(t, addr, "alice", "CORP", "Password1")
	if !bytes.Equal(NTLMServerChallenge(challenge), NTLMConf.Challenge[:]) {
		t.Fatalf("challenge = %x, want flamingo's fixed %x",
			NTLMServerChallenge(challenge), NTLMConf.Challenge[:])
	}
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE", status)
	}

	cred := recs.wait(t, "credential")
	if !strings.Contains(cred["hashcat"], hex.EncodeToString(NTLMConf.Challenge[:])) {
		t.Errorf("hashcat line %q does not carry flamingo's challenge", cred["hashcat"])
	}
	if n := recs.count("relay"); n != 0 {
		t.Errorf("%d relay records with relay off, want none", n)
	}
}

// --- relay outcomes ---------------------------------------------------------

// TestRelaySuccess checks the whole relayed path: the victim is answered with
// the target's challenge, a credential is recorded against that challenge, and
// a relay record names the target, the privilege level and the outcome.
func TestRelaySuccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin bool
		want  string
	}{
		{"administrator", true, "admin"},
		{"ordinary user", false, "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := &relayTestRecords{}
			client := &relayFakeClient{admin: tc.admin}
			conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10:445"}, nil,
				func(RelayTarget) (relay.ProtocolClient, error) { return client, nil })
			addr := relayTestSMB(t, NewRelayResponder(conf), recs)

			challenge, status := relayTestVictim(t, addr, "alice", "CORP", "Password1")

			// The victim was answered by the target, not by flamingo.
			if !bytes.Equal(NTLMServerChallenge(challenge), relayFakeChallenge) {
				t.Fatalf("challenge = %x, want the target's %x",
					NTLMServerChallenge(challenge), relayFakeChallenge)
			}
			if status != smbStatusSuccess {
				t.Errorf("status = 0x%08x, want STATUS_SUCCESS after a relay that worked", status)
			}

			// The victim's AUTHENTICATE reached the target verbatim.
			if NTLMMessageType(client.type3()) != NTLMTypeAuthenticate {
				t.Fatalf("the target was not sent an AUTHENTICATE, got %x", client.type3())
			}

			cred := recs.wait(t, "credential")
			if cred["username"] != "alice" {
				t.Errorf("credential username = %q, want alice", cred["username"])
			}
			// The hash was computed against the target's challenge, so the
			// hashcat line has to carry that one or it can never crack.
			if !strings.Contains(cred["hashcat"], hex.EncodeToString(relayFakeChallenge)) {
				t.Errorf("hashcat line %q does not carry the target's challenge %x",
					cred["hashcat"], relayFakeChallenge)
			}

			rec := recs.wait(t, "relay")
			if rec["outcome"] != relayOutcomeSuccess {
				t.Errorf("outcome = %q, want %q", rec["outcome"], relayOutcomeSuccess)
			}
			if rec["relayed"] != "true" {
				t.Errorf("relayed = %q, want true", rec["relayed"])
			}
			if rec["target"] != "smb://192.0.2.10:445" {
				t.Errorf("target = %q, want smb://192.0.2.10:445", rec["target"])
			}
			if rec["target_host"] != "192.0.2.10" || rec["target_port"] != "445" || rec["target_scheme"] != "smb" {
				t.Errorf("target fields = %q/%q/%q", rec["target_scheme"], rec["target_host"], rec["target_port"])
			}
			if rec["privilege"] != tc.want {
				t.Errorf("privilege = %q, want %q", rec["privilege"], tc.want)
			}
			if rec["username"] != "alice" || rec["domain"] != "CORP" {
				t.Errorf("relay record identity = %q\\%q, want CORP\\alice", rec["domain"], rec["username"])
			}
			if rec["_proto"] != "smb" {
				t.Errorf("_proto = %q, want smb", rec["_proto"])
			}

			// With no attacks configured the session is disconnected as
			// soon as the privilege level is known.
			deadline := time.Now().Add(2 * time.Second)
			for !client.wasKilled() && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if !client.wasKilled() {
				t.Error("the relayed session was left open with no attack configured")
			}
		})
	}
}

// TestRelayRejected checks that a target refusing the relayed credential is
// recorded as a rejection — relayed, and said no — and not as a generic
// failure. The credential is still captured.
func TestRelayRejected(t *testing.T) {
	recs := &relayTestRecords{}
	client := &relayFakeClient{authErr: errors.New("authentication failed: status=0xc000006d")}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10"}, nil,
		func(RelayTarget) (relay.ProtocolClient, error) { return client, nil })
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	_, status := relayTestVictim(t, addr, "bob", "CORP", "Hunter2")
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE after a rejected relay", status)
	}

	if cred := recs.wait(t, "credential"); cred["username"] != "bob" {
		t.Errorf("credential username = %q, want bob", cred["username"])
	}
	rec := recs.wait(t, "relay")
	if rec["outcome"] != relayOutcomeRejected {
		t.Fatalf("outcome = %q, want %q", rec["outcome"], relayOutcomeRejected)
	}
	if rec["relayed"] != "true" {
		t.Errorf("relayed = %q, want true: the credential did reach the target", rec["relayed"])
	}
	if !strings.Contains(rec["error"], "0xc000006d") {
		t.Errorf("error = %q, want the target's own reason", rec["error"])
	}
	if _, ok := rec["privilege"]; ok {
		t.Errorf("a rejected relay reported a privilege level: %q", rec["privilege"])
	}
}

// TestRelaySigningRequired checks that a target which accepts the logon and
// then refuses the session — what a signing-required target does to a relay
// with no session key — is a distinct outcome rather than a generic failure.
func TestRelaySigningRequired(t *testing.T) {
	recs := &relayTestRecords{}
	client := &relayFakeClient{
		admin:   false,
		keepErr: errors.New("tree connect failed: status=0xc0000022"),
	}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10"}, nil,
		func(RelayTarget) (relay.ProtocolClient, error) { return client, nil })
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	_, status := relayTestVictim(t, addr, "carol", "CORP", "Password1")
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE when the session was refused", status)
	}

	rec := recs.wait(t, "relay")
	if rec["outcome"] != relayOutcomeSigning {
		t.Fatalf("outcome = %q, want %q", rec["outcome"], relayOutcomeSigning)
	}
	if rec["relayed"] != "true" {
		t.Errorf("relayed = %q, want true", rec["relayed"])
	}
	if !strings.Contains(rec["error"], "signing") {
		t.Errorf("error = %q, want it to name signing", rec["error"])
	}
}

// TestRelayUnreachableTargetStillCaptures checks that a target that cannot be
// reached costs nothing: the victim is answered with flamingo's own challenge,
// the hash is captured and crackable, and the attempt is recorded as never
// having been relayed.
func TestRelayUnreachableTargetStillCaptures(t *testing.T) {
	recs := &relayTestRecords{}
	client := &relayFakeClient{initErr: errors.New("connection refused")}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10"}, nil,
		func(RelayTarget) (relay.ProtocolClient, error) { return client, nil })
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	challenge, status := relayTestVictim(t, addr, "dave", "CORP", "Password1")
	if !bytes.Equal(NTLMServerChallenge(challenge), NTLMConf.Challenge[:]) {
		t.Fatalf("challenge = %x, want a fallback to flamingo's %x",
			NTLMServerChallenge(challenge), NTLMConf.Challenge[:])
	}
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE", status)
	}

	cred := recs.wait(t, "credential")
	if !strings.Contains(cred["hashcat"], hex.EncodeToString(NTLMConf.Challenge[:])) {
		t.Errorf("hashcat line %q is not against flamingo's challenge", cred["hashcat"])
	}
	rec := recs.wait(t, "relay")
	if rec["outcome"] != relayOutcomeUnreachable {
		t.Fatalf("outcome = %q, want %q", rec["outcome"], relayOutcomeUnreachable)
	}
	if rec["relayed"] != "false" {
		t.Errorf("relayed = %q, want false: nothing was forwarded", rec["relayed"])
	}
}

// TestRelayDeadTargetDoesNotHangVictim stands up a target that accepts a
// connection and then says nothing at all, with the real SMB relay client, and
// checks that the victim is released on flamingo's own timeout rather than
// waiting on a read that never returns.
func TestRelayDeadTargetDoesNotHangVictim(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %s", err)
	}
	defer dead.Close()
	// Accept and hold: never read, never write, never close.
	held := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := dead.Accept()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	t.Cleanup(func() {
		close(held)
		for conn := range held {
			conn.Close()
		}
	})

	recs := &relayTestRecords{}
	conf := relayTestConfig(t, recs, []string{"smb://" + dead.Addr().String()},
		func(o *RelayOptions) { o.Timeout = 300 * time.Millisecond }, nil)
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	done := make(chan []byte, 1)
	go func() {
		challenge, _ := relayTestVictim(t, addr, "erin", "CORP", "Password1")
		done <- challenge
	}()

	select {
	case challenge := <-done:
		if !bytes.Equal(NTLMServerChallenge(challenge), NTLMConf.Challenge[:]) {
			t.Fatalf("challenge = %x, want a fallback to flamingo's %x",
				NTLMServerChallenge(challenge), NTLMConf.Challenge[:])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the victim was still waiting ten seconds after a dead target swallowed the negotiate")
	}

	if cred := recs.wait(t, "credential"); cred["username"] != "erin" {
		t.Errorf("credential username = %q, want erin", cred["username"])
	}
	rec := recs.wait(t, "relay")
	if rec["outcome"] != relayOutcomeUnreachable {
		t.Fatalf("outcome = %q, want %q", rec["outcome"], relayOutcomeUnreachable)
	}
	if !strings.Contains(rec["error"], "did not answer") {
		t.Errorf("error = %q, want it to say the target did not answer", rec["error"])
	}
}

// TestRelayOneShot checks that one-shot takes a target out of rotation once it
// has accepted a credential, and that a victim with nowhere left to go is
// captured rather than dropped.
func TestRelayOneShot(t *testing.T) {
	recs := &relayTestRecords{}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10"},
		func(o *RelayOptions) { o.OneShot = true },
		func(RelayTarget) (relay.ProtocolClient, error) { return &relayFakeClient{admin: true}, nil })
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	first, _ := relayTestVictim(t, addr, "alice", "CORP", "Password1")
	if !bytes.Equal(NTLMServerChallenge(first), relayFakeChallenge) {
		t.Fatalf("the first victim was not relayed: challenge %x", NTLMServerChallenge(first))
	}
	recs.wait(t, "relay")

	second, status := relayTestVictim(t, addr, "bob", "CORP", "Hunter2")
	if !bytes.Equal(NTLMServerChallenge(second), NTLMConf.Challenge[:]) {
		t.Fatalf("the second victim was relayed to a retired target: challenge %x",
			NTLMServerChallenge(second))
	}
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE", status)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && recs.count("relay") < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	var retired map[string]string
	recs.mu.Lock()
	for _, rec := range recs.all {
		if rec["_type"] == "relay" && rec["outcome"] == relayOutcomeNoTarget {
			retired = rec
		}
	}
	recs.mu.Unlock()
	if retired == nil {
		t.Fatal("the second victim produced no no-target relay record")
	}
	if retired["relayed"] != "false" {
		t.Errorf("relayed = %q, want false", retired["relayed"])
	}
}

// TestRelayPolicies checks target selection.
func TestRelayPolicies(t *testing.T) {
	targets := []string{"smb://192.0.2.10", "smb://192.0.2.11", "smb://192.0.2.12"}

	build := func(policy RelayPolicy) *RelayConfig {
		c, err := newRelayConfig(RelayOptions{Targets: targets, Policy: policy}, false)
		if err != nil {
			t.Fatalf("newRelayConfig failed: %s", err)
		}
		return c
	}

	rr := build(RelayPolicyRoundRobin)
	var seen []string
	for i := 0; i < 6; i++ {
		target, ok := rr.pick()
		if !ok {
			t.Fatal("round-robin ran out of targets")
		}
		seen = append(seen, target.String())
	}
	want := "smb://192.0.2.10:445,smb://192.0.2.11:445,smb://192.0.2.12:445," +
		"smb://192.0.2.10:445,smb://192.0.2.11:445,smb://192.0.2.12:445"
	if strings.Join(seen, ",") != want {
		t.Errorf("round-robin visited %v", seen)
	}

	first := build(RelayPolicyFirst)
	for i := 0; i < 3; i++ {
		if target, _ := first.pick(); target.String() != "smb://192.0.2.10:445" {
			t.Errorf("first-policy pick %d = %s", i, target)
		}
	}

	random := build(RelayPolicyRandom)
	for i := 0; i < 20; i++ {
		target, ok := random.pick()
		if !ok {
			t.Fatal("random ran out of targets")
		}
		if !strings.HasPrefix(target.String(), "smb://192.0.2.1") {
			t.Fatalf("random picked %s, which is not configured", target)
		}
	}

	// Retiring every target under one-shot leaves nothing to pick.
	exhausted := build(RelayPolicyRoundRobin)
	exhausted.OneShot = true
	for _, t2 := range exhausted.Targets {
		exhausted.retire(t2)
	}
	if target, ok := exhausted.pick(); ok {
		t.Errorf("pick returned %s with every target retired", target)
	}
}

// TestRelayConcurrentSessionsDoNotShareConfig checks the upstream data race
// named in docs/plan-smb-msrpc-relay.md §3: relay.Config carries per-session
// fields written without a lock, so concurrent victims must never share one.
func TestRelayConcurrentSessionsDoNotShareConfig(t *testing.T) {
	const victims = 12

	recs := &relayTestRecords{}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10"}, nil,
		func(RelayTarget) (relay.ProtocolClient, error) {
			// A client per session too: one shared client would serialise
			// what this test is trying to overlap.
			return &relayFakeClient{admin: true, negDelay: 20 * time.Millisecond}, nil
		})
	responder := NewRelayResponder(conf).(*RelayResponder)

	// Hold every session open at once by challenging without ever
	// authenticating, then look at what each one was given.
	exchanges := make([]*NTLMExchange, victims)
	var wg sync.WaitGroup
	for i := range exchanges {
		x := &NTLMExchange{
			Proto:      "smb",
			ServerAddr: "127.0.0.1:445",
			RemoteAddr: fmt.Sprintf("198.51.100.%d:49152", i+1),
			Type1:      smbTestNegotiateToken(),
		}
		exchanges[i] = x
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := responder.Challenge(x); err != nil {
				t.Errorf("Challenge failed: %s", err)
			}
		}()
	}
	wg.Wait()

	responder.m.Lock()
	configs := make(map[*relay.Config]int, victims)
	clients := make(map[relay.ProtocolClient]int, victims)
	for _, s := range responder.sessions {
		if s.cfg == nil {
			t.Fatal("a relay session has no relay.Config of its own")
		}
		configs[s.cfg]++
		clients[s.client]++
	}
	live := len(responder.sessions)
	responder.m.Unlock()

	if live != victims {
		t.Fatalf("%d live sessions, want %d", live, victims)
	}
	if len(configs) != victims {
		t.Fatalf("%d distinct relay.Config values across %d concurrent sessions: "+
			"upstream writes session fields on it without a lock, so sharing one is a data race",
			len(configs), victims)
	}
	if len(clients) != victims {
		t.Fatalf("%d distinct relay clients across %d concurrent sessions", len(clients), victims)
	}

	// Release them: the watchdog would otherwise hold the connections for
	// the length of the exchange timeout.
	for _, x := range exchanges {
		if s := responder.detach(x); s != nil {
			s.close()
		}
	}
}

// TestRelayConcurrentVictims drives real concurrent victims through the
// listener, which is what the race detector reads.
func TestRelayConcurrentVictims(t *testing.T) {
	const victims = 8

	recs := &relayTestRecords{}
	conf := relayTestConfig(t, recs, []string{"smb://192.0.2.10", "smb://192.0.2.11"}, nil,
		func(RelayTarget) (relay.ProtocolClient, error) {
			return &relayFakeClient{admin: true, negDelay: 5 * time.Millisecond}, nil
		})
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	var wg sync.WaitGroup
	for i := 0; i < victims; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			challenge, _ := relayTestVictim(t, addr, fmt.Sprintf("user%d", i), "CORP", "Password1")
			if !bytes.Equal(NTLMServerChallenge(challenge), relayFakeChallenge) {
				t.Errorf("victim %d was not relayed: challenge %x", i, NTLMServerChallenge(challenge))
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && recs.count("relay") < victims {
		time.Sleep(5 * time.Millisecond)
	}
	if n := recs.count("relay"); n != victims {
		t.Errorf("%d relay records for %d victims", n, victims)
	}
	if n := recs.count("credential"); n != victims {
		t.Errorf("%d credential records for %d victims", n, victims)
	}
}

// TestRelayToSMBListener relays into a second flamingo SMB listener using the
// real gopacket relay client, so the whole path runs against a real SMB server
// rather than a stand-in.
//
// Flamingo's own listener refuses every logon, which makes it a target that
// challenges and then says no: the victim's AUTHENTICATE genuinely reaches it
// — the target records the credential itself — and the relay is recorded as a
// rejection rather than as never having happened.
func TestRelayToSMBListener(t *testing.T) {
	targetRecs := &relayTestRecords{}
	targetAddr := relayTestSMB(t, nil, targetRecs)

	recs := &relayTestRecords{}
	conf := relayTestConfig(t, recs, []string{"smb://" + targetAddr},
		func(o *RelayOptions) { o.Timeout = 5 * time.Second }, nil)
	addr := relayTestSMB(t, NewRelayResponder(conf), recs)

	_, status := relayTestVictim(t, addr, "frank", "CORP", "Password1")
	if status != smbStatusLogonFailure {
		t.Errorf("status = 0x%08x, want STATUS_LOGON_FAILURE: the target refuses every logon", status)
	}

	// The target captured the victim's credential, which is only possible
	// if the AUTHENTICATE really was forwarded to it.
	targetCred := targetRecs.wait(t, "credential")
	if targetCred["username"] != "frank" {
		t.Fatalf("the target captured %q, want frank", targetCred["username"])
	}

	rec := recs.wait(t, "relay")
	if rec["outcome"] != relayOutcomeRejected {
		t.Fatalf("outcome = %q, want %q (the target refuses every logon)", rec["outcome"], relayOutcomeRejected)
	}
	if rec["relayed"] != "true" {
		t.Errorf("relayed = %q, want true", rec["relayed"])
	}
	if rec["target"] != "smb://"+targetAddr {
		t.Errorf("target = %q, want smb://%s", rec["target"], targetAddr)
	}
}
