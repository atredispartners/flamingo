package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"uuid"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// The SMB tests drive the listener with a client hand-rolled on the same
// x/wire codecs the server uses, rather than importing go-smb2's own client.
// The client package drags quic-go, lz4 and a Kerberos stack into the module
// graph, and x/wire already carries request encoders in both directions, so
// the realism gained does not pay for the dependency weight.

// smbTestServer spawns an SMB collector on a free port and returns the
// address plus a channel that receives captured credential records.
func smbTestServer(t *testing.T) (string, chan map[string]string, *ConfSMB) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfSMB()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnSMB(conf); err != nil {
		t.Fatalf("SpawnSMB failed: %s", err)
	}
	t.Cleanup(func() {
		conf.Shutdown()
		rw.Done()
	})
	return conf.listener.Addr().String(), got, conf
}

func smbTestDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func smbTestWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

func smbTestSend(t *testing.T, conn net.Conn, typ byte, payload []byte) {
	t.Helper()
	if err := smbWriteFrame(conn, typ, payload); err != nil {
		t.Fatalf("write frame failed: %s", err)
	}
}

func smbTestRecv(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	typ, pkt, err := smbReadFrame(conn)
	if err != nil {
		t.Fatalf("read frame failed: %s", err)
	}
	return typ, pkt
}

// smbTestNegotiate sends an SMB2 NEGOTIATE offering the given dialects and
// returns the decoded response.
func smbTestNegotiate(t *testing.T, conn net.Conn, dialects []wire.Dialect) wire.NegotiateResponseDecoder {
	t.Helper()
	req := &wire.NegotiateRequest{
		SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
		ClientGuid:   uuid.New(),
		Dialects:     dialects,
	}
	req.CreditRequestResponse = 1
	smbTestSend(t, conn, nbtSessionMessage, smbEncode(req))

	_, pkt := smbTestRecv(t, conn)
	p := wire.PacketCodec(pkt)
	if p.IsInvalidResponse() {
		t.Fatalf("negotiate reply is not a valid SMB2 response: %x", pkt)
	}
	if p.Command() != wire.SMB2_NEGOTIATE {
		t.Fatalf("negotiate reply has command %d", p.Command())
	}
	res := wire.NegotiateResponseDecoder(p.Body())
	if res.IsInvalid() {
		t.Fatalf("invalid NEGOTIATE response: %x", pkt)
	}
	return res
}

// smbTestSessionSetup sends a SESSION_SETUP carrying token and returns the
// response packet.
func smbTestSessionSetup(t *testing.T, conn net.Conn, messageID uint64, token []byte) []byte {
	t.Helper()
	req := &wire.SessionSetupRequest{
		SecurityMode:   wire.SMB2_NEGOTIATE_SIGNING_ENABLED,
		SecurityBuffer: token,
	}
	req.CreditRequestResponse = 1
	req.MessageId = messageID
	smbTestSend(t, conn, nbtSessionMessage, smbEncode(req))
	_, pkt := smbTestRecv(t, conn)
	return pkt
}

// smbTestNegotiateToken is a minimal NTLMSSP NEGOTIATE message.
func smbTestNegotiateToken() []byte {
	m := make([]byte, 40)
	copy(m, ntlmSignature)
	binary.LittleEndian.PutUint32(m[8:], NTLMTypeNegotiate)
	binary.LittleEndian.PutUint32(m[12:], NTLMFlagUnicode|NTLMFlagNTLM|NTLMFlagRequestTarget|
		NTLMFlagExtendedSessionSecurity|NTLMFlagVersion|NTLMFlagAlwaysSign)
	copy(m[32:40], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})
	return m
}

// smbTestChallengeFrom pulls the CHALLENGE message out of a SESSION_SETUP
// response, failing when the status is not STATUS_MORE_PROCESSING_REQUIRED.
func smbTestChallengeFrom(t *testing.T, pkt []byte) []byte {
	t.Helper()
	p := wire.PacketCodec(pkt)
	if p.IsInvalidResponse() {
		t.Fatalf("session setup reply is not a valid SMB2 response: %x", pkt)
	}
	if p.Status() != smbStatusMoreProcessingRequired {
		t.Fatalf("session setup status 0x%08x, want STATUS_MORE_PROCESSING_REQUIRED", p.Status())
	}
	res := wire.SessionSetupResponseDecoder(p.Body())
	if res.IsInvalid() {
		t.Fatalf("invalid SESSION_SETUP response: %x", pkt)
	}
	msg := FindNTLMSSP(res.SecurityBuffer())
	if NTLMMessageType(msg) != NTLMTypeChallenge {
		t.Fatalf("security buffer does not carry a CHALLENGE: %x", res.SecurityBuffer())
	}
	return msg
}

// smbTestTargetInfo returns the AV_PAIR block of a CHALLENGE message.
func smbTestTargetInfo(t *testing.T, challenge []byte) []byte {
	t.Helper()
	info := ntlmSecBuf(challenge, 40)
	if len(info) == 0 {
		t.Fatal("CHALLENGE carries no target info")
	}
	return info
}

func TestSMBPickDialect(t *testing.T) {
	tests := []struct {
		name    string
		offered []wire.Dialect
		want    uint16
		dotted  string
	}{
		{"modern client", []wire.Dialect{wire.SMB202, wire.SMB210, wire.SMB300, wire.SMB302, wire.SMB311}, wire.SMB311, "3.1.1"},
		{"highest wins regardless of order", []wire.Dialect{wire.SMB311, wire.SMB202}, wire.SMB311, "3.1.1"},
		{"win7 era", []wire.Dialect{wire.SMB202, wire.SMB210}, wire.SMB210, "2.1"},
		{"vista era", []wire.Dialect{wire.SMB202}, wire.SMB202, "2.0.2"},
		{"smb 3.0.2 only", []wire.Dialect{wire.SMB302}, wire.SMB302, "3.0.2"},
		{"unknown future dialect", []wire.Dialect{0x0400}, 0, ""},
		{"wildcard is never selected", []wire.Dialect{smb1WildcardDialect}, 0, ""},
		{"empty", nil, 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := smbPickDialect(tc.offered)
			if got != tc.want {
				t.Fatalf("smbPickDialect = 0x%04x, want 0x%04x", got, tc.want)
			}
			if tc.want != 0 && smbDialectName(got) != tc.dotted {
				t.Fatalf("smbDialectName(0x%04x) = %q, want %q", got, smbDialectName(got), tc.dotted)
			}
		})
	}
}

// TestSMBNegotiate311 checks that a client offering everything gets SMB 3.1.1
// with the preauth-integrity and encryption contexts, signing enabled and
// never signing required.
func TestSMBNegotiate311(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	res := smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB202, wire.SMB210, wire.SMB300, wire.SMB302, wire.SMB311})
	if res.DialectRevision() != wire.SMB311 {
		t.Fatalf("negotiated 0x%04x, want 0x%04x", res.DialectRevision(), wire.SMB311)
	}
	if res.SecurityMode()&wire.SMB2_NEGOTIATE_SIGNING_ENABLED == 0 {
		t.Error("SMB2_NEGOTIATE_SIGNING_ENABLED not advertised")
	}
	// Signing required must never be advertised: a client that insists on
	// signing still completes SESSION_SETUP, which is all the capture needs.
	if res.SecurityMode()&wire.SMB2_NEGOTIATE_SIGNING_REQUIRED != 0 {
		t.Error("SMB2_NEGOTIATE_SIGNING_REQUIRED advertised")
	}
	if res.NegotiateContextCount() != 2 {
		t.Fatalf("negotiate context count = %d, want 2", res.NegotiateContextCount())
	}
	if FindNTLMSSP(res.SecurityBuffer()) != nil {
		t.Error("NEGOTIATE security buffer should be a SPNEGO negTokenInit2, not a raw NTLM message")
	}
	if !bytes.Contains(res.SecurityBuffer(), smbMechNTLMSSP) {
		t.Error("NEGOTIATE security buffer does not advertise the NTLMSSP mechanism")
	}
}

// TestSMBNegotiate210 checks that an older client is answered without the
// SMB 3.1.1 negotiate contexts.
func TestSMBNegotiate210(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	res := smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB202, wire.SMB210})
	if res.DialectRevision() != wire.SMB210 {
		t.Fatalf("negotiated 0x%04x, want 0x%04x", res.DialectRevision(), wire.SMB210)
	}
	if res.NegotiateContextCount() != 0 {
		t.Errorf("negotiate context count = %d, want 0 below SMB 3.1.1", res.NegotiateContextCount())
	}
}

// TestSMBNegotiateNoDialect checks that a client offering nothing we speak is
// refused rather than answered with a guess.
func TestSMBNegotiateNoDialect(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	req := &wire.NegotiateRequest{Dialects: []wire.Dialect{0x0400}}
	req.CreditRequestResponse = 1
	smbTestSend(t, conn, nbtSessionMessage, smbEncode(req))

	_, pkt := smbTestRecv(t, conn)
	if status := wire.PacketCodec(pkt).Status(); status != smbStatusNotSupported {
		t.Fatalf("status 0x%08x, want STATUS_NOT_SUPPORTED", status)
	}
}

// TestSMBCaptureNTLMv2 runs the full NEGOTIATE and SESSION_SETUP exchange with
// a genuine NetNTLMv2 response and checks the recorded fields and hashcat line.
func TestSMBCaptureNTLMv2(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	res := smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB210, wire.SMB311})
	if res.DialectRevision() != wire.SMB311 {
		t.Fatalf("negotiated 0x%04x", res.DialectRevision())
	}

	reply := smbTestSessionSetup(t, conn, 1, smbSPNEGONegTokenResp(smbTestNegotiateToken()))
	challenge := smbTestChallengeFrom(t, reply)
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("server challenge = %x, want %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	blob := ntlmTestV2Blob(smbTestTargetInfo(t, challenge), false)
	proof := ntlmTestV2Proof("Password1", "alice", "CORP", NTLMConf.Challenge[:], blob)
	nt := append(append([]byte(nil), proof...), blob...)
	auth := ntlmTestAuthMsg("alice", "CORP", "WS01", nil, nt, nil, 0)

	reply = smbTestSessionSetup(t, conn, 2, smbSPNEGONegTokenResp(auth))
	if status := wire.PacketCodec(reply).Status(); status != smbStatusLogonFailure {
		t.Fatalf("status 0x%08x, want STATUS_LOGON_FAILURE", status)
	}

	rec := smbTestWaitCred(t, got)
	want := map[string]string{
		"_type":        "credential",
		"_proto":       "smb",
		"username":     "alice",
		"domain":       "CORP",
		"workstation":  "WS01",
		"ntlm_version": "v2",
		"dialect":      "3.1.1",
		"hashcat_mode": "5600",
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
	if rec["client_version"] != "10.0.19043" {
		t.Errorf("client_version = %q, want %q", rec["client_version"], "10.0.19043")
	}
	if !strings.HasSuffix(rec["_server"], ":0") {
		t.Errorf("_server = %q, want the configured bind address", rec["_server"])
	}
	if !strings.HasPrefix(rec["_host"], "127.0.0.1:") {
		t.Errorf("_host = %q, want the client address", rec["_host"])
	}
}

// TestSMBCaptureNTLMv1 checks the mode 5500 layout, which puts the
// workstation rather than the domain in the second field.
func TestSMBCaptureNTLMv1(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB210})
	reply := smbTestSessionSetup(t, conn, 1, smbSPNEGONegTokenResp(smbTestNegotiateToken()))
	smbTestChallengeFrom(t, reply)

	nt := ntlmTestV1Response("Password1", NTLMConf.Challenge[:])
	lm := make([]byte, 24)
	auth := ntlmTestAuthMsg("bob", "CORP", "OLDBOX", lm, nt, nil, 0)

	reply = smbTestSessionSetup(t, conn, 2, smbSPNEGONegTokenResp(auth))
	if status := wire.PacketCodec(reply).Status(); status != smbStatusLogonFailure {
		t.Fatalf("status 0x%08x, want STATUS_LOGON_FAILURE", status)
	}

	rec := smbTestWaitCred(t, got)
	if rec["ntlm_version"] != "v1" || rec["hashcat_mode"] != "5500" {
		t.Fatalf("ntlm_version=%q hashcat_mode=%q, want v1/5500", rec["ntlm_version"], rec["hashcat_mode"])
	}
	if rec["dialect"] != "2.1" {
		t.Errorf("dialect = %q, want 2.1", rec["dialect"])
	}
	wantLine := fmt.Sprintf("bob::OLDBOX:%s:%s:%s", hex.EncodeToString(lm),
		hex.EncodeToString(nt), hex.EncodeToString(NTLMConf.Challenge[:]))
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
}

// TestSMBNetBIOSSessionRequest drives the port 139 path: the session service
// request is answered before any SMB framing, and the calling name becomes the
// workstation when the AUTHENTICATE message carries none.
func TestSMBNetBIOSSessionRequest(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionRequest, smbTestSessionRequest("*SMBSERVER", "OLDCLIENT"))
	typ, body := smbTestRecv(t, conn)
	if typ != nbtPositiveResponse {
		t.Fatalf("NetBIOS reply type 0x%02x, want 0x%02x", typ, nbtPositiveResponse)
	}
	if len(body) != 0 {
		t.Fatalf("positive session response carries %d bytes, want 0", len(body))
	}

	smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB210})
	reply := smbTestSessionSetup(t, conn, 1, smbSPNEGONegTokenResp(smbTestNegotiateToken()))
	challenge := smbTestChallengeFrom(t, reply)

	blob := ntlmTestV2Blob(smbTestTargetInfo(t, challenge), false)
	proof := ntlmTestV2Proof("Password1", "carol", "CORP", NTLMConf.Challenge[:], blob)
	auth := ntlmTestAuthMsg("carol", "CORP", "", nil, append(append([]byte(nil), proof...), blob...), nil, 0)
	smbTestSessionSetup(t, conn, 2, smbSPNEGONegTokenResp(auth))

	rec := smbTestWaitCred(t, got)
	if rec["workstation"] != "OLDCLIENT" {
		t.Errorf("workstation = %q, want the NetBIOS calling name", rec["workstation"])
	}
}

func TestSMBNBTCallingName(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want string
	}{
		{"well formed", smbTestSessionRequest("*SMBSERVER", "WS01"), "WS01"},
		{"short", smbTestSessionRequest("*SMBSERVER", "WS01")[:40], ""},
		{"empty", nil, ""},
		{"bad length byte", append([]byte{0x10}, make([]byte, 80)...), ""},
		{"non level-1 encoding", append([]byte{32}, bytes.Repeat([]byte{0xff}, 80)...), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := smbNBTCallingName(tc.pkt); got != tc.want {
				t.Fatalf("smbNBTCallingName = %q, want %q", got, tc.want)
			}
		})
	}
}

// smbTestSessionRequest builds a NetBIOS session request payload.
func smbTestSessionRequest(called, calling string) []byte {
	out := append(smbTestNBTName(called), smbTestNBTName(calling)...)
	return out
}

// smbTestNBTName first-level encodes a NetBIOS name.
func smbTestNBTName(name string) []byte {
	padded := make([]byte, 16)
	copy(padded, strings.ToUpper(name))
	for i := len(name); i < 15; i++ {
		padded[i] = ' '
	}
	out := []byte{32}
	for _, c := range padded {
		out = append(out, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	return append(out, 0)
}

func TestSMBSPNEGOTokens(t *testing.T) {
	init := smbSPNEGONegTokenInit2()
	if init[0] != 0x60 {
		t.Fatalf("negTokenInit2 tag = 0x%02x, want 0x60", init[0])
	}
	if !bytes.Contains(init, smbOIDSPNEGO) || !bytes.Contains(init, smbMechNTLMSSP) {
		t.Error("negTokenInit2 is missing the SPNEGO or NTLMSSP OID")
	}

	// A CHALLENGE large enough to need a two-byte DER length must survive the
	// wrapping intact.
	challenge := NTLMChallengeMessage(0)
	if len(challenge) < 0x80 {
		t.Fatalf("CHALLENGE is only %d bytes; the long-form length is untested", len(challenge))
	}
	resp := smbSPNEGONegTokenResp(challenge)
	if resp[0] != 0xa1 {
		t.Fatalf("negTokenResp tag = 0x%02x, want 0xa1", resp[0])
	}
	if !bytes.Equal(FindNTLMSSP(resp), challenge) {
		t.Error("the CHALLENGE did not survive the negTokenResp wrapping")
	}
}

func TestSMBDER(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []byte
	}{
		{"short form", 3, []byte{0x04, 0x03}},
		{"short form boundary", 0x7f, []byte{0x04, 0x7f}},
		{"one byte long form", 0x80, []byte{0x04, 0x81, 0x80}},
		{"two byte long form", 0x100, []byte{0x04, 0x82, 0x01, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := smbDER(0x04, make([]byte, tc.n))
			if !bytes.HasPrefix(out, tc.want) {
				t.Fatalf("header = %x, want %x", out[:len(tc.want)], tc.want)
			}
			if len(out) != len(tc.want)+tc.n {
				t.Fatalf("length = %d, want %d", len(out), len(tc.want)+tc.n)
			}
		})
	}
}

// TestSMBMalformed feeds the listener truncated and nonsensical messages. None
// may panic, and every one must end with the connection closed rather than a
// goroutine left waiting.
func TestSMBMalformed(t *testing.T) {
	addr, _, _ := smbTestServer(t)

	negotiated := func(dialects []wire.Dialect) []byte {
		req := &wire.NegotiateRequest{Dialects: dialects}
		req.CreditRequestResponse = 1
		return smbEncode(req)
	}
	truncate := func(b []byte, n int) []byte { return b[:n] }

	tests := []struct {
		name string
		pkts [][]byte
	}{
		{"empty frame", [][]byte{{}}},
		{"one byte", [][]byte{{0xfe}}},
		{"header only", [][]byte{make([]byte, 64)}},
		{"smb2 magic without a body", [][]byte{append([]byte{0xfe, 'S', 'M', 'B'}, make([]byte, 60)...)}},
		{"response flag set on a request", [][]byte{func() []byte {
			pkt := negotiated([]wire.Dialect{wire.SMB210})
			wire.PacketCodec(pkt).SetFlags(wire.SMB2_FLAGS_SERVER_TO_REDIR)
			return pkt
		}()}},
		{"negotiate truncated mid dialects", [][]byte{truncate(negotiated([]wire.Dialect{wire.SMB202, wire.SMB311}), 68)}},
		{"negotiate claiming more dialects than it carries", [][]byte{func() []byte {
			pkt := negotiated([]wire.Dialect{wire.SMB210})
			binary.LittleEndian.PutUint16(pkt[66:68], 500)
			return pkt
		}()}},
		{"session setup before negotiate", [][]byte{func() []byte {
			req := &wire.SessionSetupRequest{SecurityBuffer: smbTestNegotiateToken()}
			req.CreditRequestResponse = 1
			return smbEncode(req)
		}()}},
		{"session setup with a lying security buffer", [][]byte{
			negotiated([]wire.Dialect{wire.SMB210}),
			func() []byte {
				req := &wire.SessionSetupRequest{SecurityBuffer: smbTestNegotiateToken()}
				req.CreditRequestResponse = 1
				pkt := smbEncode(req)
				binary.LittleEndian.PutUint16(pkt[78:80], 0xffff) // SecurityBufferLength
				return pkt
			}(),
		}},
		{"session setup with a non NTLM token", [][]byte{
			negotiated([]wire.Dialect{wire.SMB210}),
			func() []byte {
				req := &wire.SessionSetupRequest{SecurityBuffer: []byte("not a gss token")}
				req.CreditRequestResponse = 1
				return smbEncode(req)
			}(),
		}},
		{"authenticate truncated to its signature", [][]byte{
			negotiated([]wire.Dialect{wire.SMB210}),
			func() []byte {
				msg := append(append([]byte(nil), ntlmSignature...), 3, 0, 0, 0)
				req := &wire.SessionSetupRequest{SecurityBuffer: smbSPNEGONegTokenResp(msg)}
				req.CreditRequestResponse = 1
				return smbEncode(req)
			}(),
		}},
		{"tree connect without a session", [][]byte{
			negotiated([]wire.Dialect{wire.SMB210}),
			func() []byte {
				pkt := make([]byte, 64+9)
				p := wire.PacketCodec(pkt)
				p.SetProtocolId()
				p.SetStructureSize()
				p.SetCommand(wire.SMB2_TREE_CONNECT)
				p.SetCreditRequest(1)
				return pkt
			}(),
		}},
		{"smb1 magic with nothing after it", [][]byte{append([]byte{0xff, 'S', 'M', 'B'}, make([]byte, 28)...)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := smbTestDial(t, addr)
			for _, pkt := range tc.pkts {
				if err := smbWriteFrame(conn, nbtSessionMessage, pkt); err != nil {
					return // the server hung up first, which is a valid outcome
				}
			}
			// The server must either answer or close. Going quiet without
			// doing either would mean a goroutine parked on a read with no
			// deadline.
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			answered := 0
			for {
				_, _, err := smbReadFrame(conn)
				if err == nil {
					answered++
					continue
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() && answered == 0 {
					t.Fatal("server neither answered nor closed the connection")
				}
				return
			}
		})
	}
}

// TestSMBOversizedFrame checks the per-message cap: a frame larger than the
// limit is refused without allocating it.
func TestSMBOversizedFrame(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, smbMaxMessage+1)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := smbReadFrame(conn); err == nil {
		t.Fatal("server accepted an oversized frame")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server did not close the connection after an oversized frame")
	}
}

// TestSMBMessageLimit checks that a client cannot keep a connection alive
// forever by sending NetBIOS keepalives.
func TestSMBMessageLimit(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	for i := 0; i < smbMaxMessages+4; i++ {
		if err := smbWriteFrame(conn, nbtKeepAlive, nil); err != nil {
			return
		}
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := smbReadFrame(conn); err == nil {
		t.Fatal("server replied to a keepalive")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept the connection past the message limit")
	}
}

func TestSMBShutdown(t *testing.T) {
	_, _, conf := smbTestServer(t)
	if conf.IsShutdown() {
		t.Fatal("a freshly spawned listener reports shutdown")
	}
	conf.Shutdown()
	if !conf.IsShutdown() {
		t.Fatal("IsShutdown is false after Shutdown")
	}
	conf.Shutdown() // must stay safe when called twice
}

func TestNewConfSMB(t *testing.T) {
	conf := NewConfSMB()
	if conf.BindPort != 445 {
		t.Errorf("default port = %d, want 445", conf.BindPort)
	}
	if conf.BindHost != "[::]" {
		t.Errorf("default host = %q, want [::]", conf.BindHost)
	}
	if conf.serverGUID == (uuid.UUID{}) {
		t.Error("server GUID was not generated")
	}
}
