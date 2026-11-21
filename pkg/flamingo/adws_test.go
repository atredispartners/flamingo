package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// The ADWS tests drive the listener over a real socket, speaking the MC-NMF
// framing preamble and the NegotiateStream handshake an Active Directory Web
// Services client sends to port 9389.

// adwsTestServer spawns an ADWS collector on a free port.
func adwsTestServer(t *testing.T) (string, chan map[string]string, *ConfADWS) {
	t.Helper()
	rw, got := captureTestWriter(t)

	conf := NewConfADWS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw

	if err := SpawnADWS(conf); err != nil {
		t.Fatalf("SpawnADWS failed: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return fmt.Sprintf("127.0.0.1:%d", conf.BindPort), got, conf
}

func adwsTestDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

// adwsTestPreamble is the MC-NMF preamble an ADWS client sends: version, mode,
// via URL, encoding and a request to upgrade the stream to Negotiate.
func adwsTestPreamble(via, upgrade string) []byte {
	var b bytes.Buffer
	b.Write([]byte{nmfVersionRecord, 0x01, 0x00})
	b.Write([]byte{nmfModeRecord, 0x01})
	b.WriteByte(nmfViaRecord)
	b.Write(adwsTestSize(len(via)))
	b.WriteString(via)
	b.Write([]byte{nmfKnownEncodingRecord, 0x08})
	b.WriteByte(nmfUpgradeRequest)
	b.Write(adwsTestSize(len(upgrade)))
	b.WriteString(upgrade)
	return b.Bytes()
}

// adwsTestSize encodes a .NET 7-bit variable-length integer.
func adwsTestSize(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

// adwsTestHandshake frames one NegotiateStream handshake record.
func adwsTestHandshake(id byte, payload []byte) []byte {
	rec := []byte{id, 0x01, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	return append(rec, payload...)
}

// adwsTestReadHandshake reads one handshake record back.
func adwsTestReadHandshake(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reading a handshake header: %s", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 {
		return hdr[0], nil
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(conn, blob); err != nil {
		t.Fatalf("reading a handshake payload: %s", err)
	}
	return hdr[0], blob
}

// adwsTestUpgrade sends the preamble and consumes the upgrade response.
func adwsTestUpgrade(t *testing.T, conn net.Conn) {
	t.Helper()
	pre := adwsTestPreamble("net.tcp://dc01.corp.local:9389/ActiveDirectoryWebServices/Windows/Resource", adwsUpgrade)
	if _, err := conn.Write(pre); err != nil {
		t.Fatalf("sending the preamble: %s", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("reading the upgrade response: %s", err)
	}
	if resp[0] != nmfUpgradeResponse {
		t.Fatalf("upgrade response is 0x%02x, want 0x%02x", resp[0], nmfUpgradeResponse)
	}
}

// TestADWSCaptureNTLMv2 runs the whole exchange with the SPNEGO wrapping a
// real client uses.
func TestADWSCaptureNTLMv2(t *testing.T) {
	addr, got, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)

	negotiate := smbSPNEGONegTokenInit2WithToken(captureTestNegotiate())
	if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, negotiate)); err != nil {
		t.Fatalf("sending the NEGOTIATE: %s", err)
	}

	id, blob := adwsTestReadHandshake(t, conn)
	if id != nnsHandshakeInProgress {
		t.Fatalf("challenge record is 0x%02x, want handshake_in_progress", id)
	}
	challenge := FindNTLMSSP(blob)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("the handshake record carries no CHALLENGE: %x", blob)
	}
	if len(blob) == len(challenge) {
		t.Error("the CHALLENGE came back unwrapped although the NEGOTIATE was SPNEGO wrapped")
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, proof, blob2 := captureTestV2Auth(t, challenge, "adws", "CORP", "WS30", "Spring2026!")
	if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, smbSPNEGONegTokenResp(msg))); err != nil {
		t.Fatalf("sending the AUTHENTICATE: %s", err)
	}

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("adws::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob2))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "5600" {
		t.Errorf("hashcat_mode is %q, want 5600", rec["hashcat_mode"])
	}
	if rec["_proto"] != "adws" {
		t.Errorf("_proto is %q, want adws", rec["_proto"])
	}
	if rec["_server"] != addr {
		t.Errorf("_server is %q, want %q", rec["_server"], addr)
	}
	if rec["username"] != "adws" || rec["domain"] != "CORP" || rec["workstation"] != "WS30" {
		t.Errorf("identity fields are %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}

	// Capture only: the handshake ends in an error, not a completed logon.
	id, payload := adwsTestReadHandshake(t, conn)
	if id != nnsHandshakeError {
		t.Errorf("final record is 0x%02x, want handshake_error", id)
	}
	if len(payload) >= 8 && binary.BigEndian.Uint32(payload[4:8]) != nnsLogonDenied {
		t.Errorf("handshake error carries HRESULT 0x%08x", binary.BigEndian.Uint32(payload[4:8]))
	}
}

// TestADWSCaptureRawNTLM covers a client that skips SPNEGO and puts the
// NTLMSSP messages straight into the handshake records.
func TestADWSCaptureRawNTLM(t *testing.T) {
	addr, got, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)

	if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, captureTestNegotiate())); err != nil {
		t.Fatalf("sending the NEGOTIATE: %s", err)
	}
	id, blob := adwsTestReadHandshake(t, conn)
	if id != nnsHandshakeInProgress {
		t.Fatalf("challenge record is 0x%02x", id)
	}
	if NTLMMessageType(blob) != NTLMTypeChallenge {
		t.Fatalf("a raw NEGOTIATE was answered with a wrapped CHALLENGE: %x", blob)
	}

	msg, _, _ := captureTestV2Auth(t, blob, "raw", "CORP", "WS31", "pass")
	if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, msg)); err != nil {
		t.Fatalf("sending the AUTHENTICATE: %s", err)
	}

	rec := captureTestRecord(t, got)
	if rec["username"] != "raw" {
		t.Errorf("username is %q, want raw", rec["username"])
	}
}

// TestADWSEmptyHandshakeBlob is the case that crashes gopacket's own WCF
// server: a correctly framed handshake record with a zero-length payload. It
// has to be answered, not indexed into.
func TestADWSEmptyHandshakeBlob(t *testing.T) {
	addr, got, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)

	// Several empty records, then a real NEGOTIATE: the listener survives
	// the empty ones and still captures the credential.
	for i := 0; i < 3; i++ {
		if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, nil)); err != nil {
			t.Fatalf("sending an empty record: %s", err)
		}
		if id, _ := adwsTestReadHandshake(t, conn); id != nnsHandshakeInProgress {
			t.Fatalf("empty record answered with 0x%02x", id)
		}
	}

	if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, captureTestNegotiate())); err != nil {
		t.Fatalf("sending the NEGOTIATE: %s", err)
	}
	id, challenge := adwsTestReadHandshake(t, conn)
	if id != nnsHandshakeInProgress || NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("no CHALLENGE after the empty records: 0x%02x %x", id, challenge)
	}

	msg, _, _ := captureTestV2Auth(t, challenge, "persistent", "CORP", "WS32", "pass")
	conn.Write(adwsTestHandshake(nnsHandshakeInProgress, msg))
	if rec := captureTestRecord(t, got); rec["username"] != "persistent" {
		t.Errorf("username is %q, want persistent", rec["username"])
	}
}

// TestADWSEmptyBlobAfterChallenge covers the second zero-length case, where
// the empty record arrives where the AUTHENTICATE belongs.
func TestADWSEmptyBlobAfterChallenge(t *testing.T) {
	addr, got, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)

	conn.Write(adwsTestHandshake(nnsHandshakeInProgress, captureTestNegotiate()))
	adwsTestReadHandshake(t, conn)
	conn.Write(adwsTestHandshake(nnsHandshakeInProgress, nil))

	// The connection is dropped rather than crashing the process, and no
	// credential is invented.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.Copy(io.Discard, conn)

	select {
	case rec := <-got:
		t.Errorf("an empty record produced a credential: %v", rec)
	case <-time.After(100 * time.Millisecond):
	}

	// The listener is still serving.
	next := adwsTestDial(t, addr)
	adwsTestUpgrade(t, next)
}

// TestADWSRejectsNonNegotiateUpgrade checks a client asking for an upgrade
// the listener cannot speak is faulted rather than left hanging.
func TestADWSRejectsNonNegotiateUpgrade(t *testing.T) {
	addr, _, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)

	pre := adwsTestPreamble("net.tcp://dc01:9389/ADWS", "application/ssl-tls")
	if _, err := conn.Write(pre); err != nil {
		t.Fatalf("sending the preamble: %s", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("reading the fault: %s", err)
	}
	if resp[0] != nmfFault {
		t.Errorf("reply is 0x%02x, want a fault", resp[0])
	}
}

// TestADWSMalformed throws rubbish at the listener. Nothing may panic or
// hang, and the listener has to stay up.
func TestADWSMalformed(t *testing.T) {
	addr, got, _ := adwsTestServer(t)

	cases := []struct {
		name string
		send []byte
	}{
		{"empty", nil},
		{"wrong first record", []byte{0x42, 0x01, 0x00}},
		{"preamble cut short", []byte{nmfVersionRecord, 0x01}},
		{"via length never satisfied", []byte{nmfVersionRecord, 0x01, 0x00, nmfModeRecord, 0x01, nmfViaRecord, 0x40}},
		{"via size five bytes of continuation", []byte{nmfVersionRecord, 0x01, 0x00, nmfModeRecord, 0x01,
			nmfViaRecord, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"oversized via", append([]byte{nmfVersionRecord, 0x01, 0x00, nmfModeRecord, 0x01, nmfViaRecord},
			adwsTestSize(1<<20)...)},
		{"handshake before the upgrade", adwsTestHandshake(nnsHandshakeInProgress, captureTestNegotiate())},
		{"http request", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"random bytes", bytes.Repeat([]byte{0xa5}, 256)},
		{"preamble then unknown handshake id", append(
			adwsTestPreamble("net.tcp://dc01:9389/ADWS", adwsUpgrade),
			adwsTestHandshake(0x99, []byte("whatever"))...)},
		{"preamble then an authenticate with no negotiate", append(
			adwsTestPreamble("net.tcp://dc01:9389/ADWS", adwsUpgrade),
			adwsTestHandshake(nnsHandshakeInProgress,
				ntlmTestAuthMsg("ghost", "CORP", "WS", nil, make([]byte, 24), nil, 0))...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %s", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			conn.Write(tc.send)
			io.Copy(io.Discard, conn)
		})
	}

	select {
	case rec := <-got:
		t.Errorf("malformed input produced a credential: %v", rec)
	default:
	}

	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)
}

// TestADWSHandshakeRecordLimit checks a client that never sends an NTLM
// NEGOTIATE is dropped after a bounded number of records rather than looping.
func TestADWSHandshakeRecordLimit(t *testing.T) {
	addr, _, _ := adwsTestServer(t)
	conn := adwsTestDial(t, addr)
	adwsTestUpgrade(t, conn)

	for i := 0; i < adwsMaxRecords+4; i++ {
		if _, err := conn.Write(adwsTestHandshake(nnsHandshakeInProgress, []byte{0x60, 0x00})); err != nil {
			break
		}
	}
	// The connection ends, one way or another: a reset while the listener is
	// still being written at is as good as a clean close. What must not
	// happen is the read sitting there until the deadline.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err := io.Copy(io.Discard, conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("the listener never dropped a client that would not authenticate")
	}
}

// TestADWSDisconnectMidExchange checks the adapter releases victims that
// negotiate and then drop.
func TestADWSDisconnectMidExchange(t *testing.T) {
	addr, _, conf := adwsTestServer(t)
	conf.capture.Timeout = 200 * time.Millisecond

	settle(t, 0)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %s", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		adwsTestUpgrade(t, conn)
		conn.Write(adwsTestHandshake(nnsHandshakeInProgress, captureTestNegotiate()))
		if i%2 == 0 {
			adwsTestReadHandshake(t, conn)
		}
		conn.Close()
	}

	conf.Shutdown()
	settle(t, before)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines went from %d to %d across 20 abandoned exchanges", before, after)
	}
}

func TestADWSShutdown(t *testing.T) {
	addr, _, conf := adwsTestServer(t)
	adwsTestDial(t, addr)

	start := time.Now()
	conf.Shutdown()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Shutdown took %s", elapsed)
	}
	if !conf.IsShutdown() {
		t.Error("IsShutdown is false after Shutdown")
	}
	conf.Shutdown()

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("the port is still accepting connections after Shutdown")
	}
}

func TestADWSSizeEncoding(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 300, 4096} {
		r := &adwsReader{r: bytes.NewReader(adwsTestSize(n))}
		got, err := r.size()
		if err != nil {
			t.Fatalf("decoding %d: %s", n, err)
		}
		if got != n {
			t.Errorf("decoded %d, want %d", got, n)
		}
	}

	// Beyond the per-connection limit, and a size that never terminates.
	r := &adwsReader{r: bytes.NewReader(adwsTestSize(1 << 20))}
	if _, err := r.size(); err == nil {
		t.Error("an oversized record size was accepted")
	}
	r = &adwsReader{r: bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})}
	if _, err := r.size(); err == nil {
		t.Error("a record size longer than five bytes was accepted")
	}
}

func TestNewConfADWS(t *testing.T) {
	conf := NewConfADWS()
	if conf.BindPort != 9389 {
		t.Errorf("default port is %d, want 9389", conf.BindPort)
	}
	if conf.BindHost != "[::]" {
		t.Errorf("default host is %q, want [::]", conf.BindHost)
	}
	if conf.IsShutdown() {
		t.Error("a fresh configuration reports itself shut down")
	}
}

func TestADWSSpawnAfterShutdown(t *testing.T) {
	rw, _ := captureTestWriter(t)
	conf := NewConfADWS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw
	conf.Shutdown()

	if err := SpawnADWS(conf); err == nil {
		t.Fatal("spawning an already shut down listener succeeded")
	}
}
