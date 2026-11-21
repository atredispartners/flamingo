package flamingo

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// WinRM is NTLM over HTTP on /wsman, so the tests speak HTTP down a single
// keep-alive connection: upstream keys its NTLM session on the connection's
// remote address, and the NEGOTIATE and AUTHENTICATE arrive in two separate
// requests.

// winrmTestServer spawns a WinRM collector on a free port.
func winrmTestServer(t *testing.T) (string, chan map[string]string, *ConfWinRM) {
	t.Helper()
	rw, got := captureTestWriter(t)

	conf := NewConfWinRM()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw

	if err := SpawnWinRM(conf); err != nil {
		t.Fatalf("SpawnWinRM failed: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return fmt.Sprintf("127.0.0.1:%d", conf.BindPort), got, conf
}

// winrmTestConn is one keep-alive HTTP connection to a capture listener.
type winrmTestConn struct {
	conn net.Conn
	br   *bufio.Reader
	addr string
}

func winrmTestDial(t *testing.T, addr string) *winrmTestConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return &winrmTestConn{conn: conn, br: bufio.NewReader(conn), addr: addr}
}

func winrmTestDialTLS(t *testing.T, addr string) *winrmTestConn {
	t.Helper()
	// The listener presents a self-signed certificate it generated itself,
	// which is the point: a victim that trusts nothing still authenticates.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("TLS dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return &winrmTestConn{conn: conn, br: bufio.NewReader(conn), addr: addr}
}

// do sends one WSMan-shaped request, optionally carrying an NTLM token, and
// returns the response.
func (c *winrmTestConn) do(t *testing.T, token []byte) *http.Response {
	t.Helper()
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST /wsman HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n", c.addr)
	if token != nil {
		fmt.Fprintf(&req, "Authorization: NTLM %s\r\n", base64.StdEncoding.EncodeToString(token))
	}
	req.WriteString("\r\n")

	if _, err := c.conn.Write(req.Bytes()); err != nil {
		t.Fatalf("sending a request: %s", err)
	}
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("reading a response: %s", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// winrmTestAuthToken pulls the NTLM token out of a WWW-Authenticate header.
func winrmTestAuthToken(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	hdr := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(hdr, "NTLM ") {
		t.Fatalf("WWW-Authenticate is %q, want an NTLM token", hdr)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "NTLM "))
	if err != nil {
		t.Fatalf("decoding the NTLM token: %s", err)
	}
	return raw
}

// winrmTestCapture runs the whole NTLM-over-HTTP exchange and checks the
// recorded credential. It is shared by the 5985 and 5986 listeners, which are
// the same server with and without TLS.
func winrmTestCapture(t *testing.T, c *winrmTestConn, got chan map[string]string, proto, addr, user string) {
	t.Helper()

	// An unauthenticated request draws the NTLM offer.
	resp := c.do(t, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request got %d, want 401", resp.StatusCode)
	}
	if hdr := resp.Header.Get("WWW-Authenticate"); hdr != "NTLM" {
		t.Fatalf("WWW-Authenticate is %q, want a bare NTLM offer", hdr)
	}

	// The NEGOTIATE is answered with flamingo's fixed-challenge CHALLENGE.
	resp = c.do(t, captureTestNegotiate())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("NEGOTIATE got %d, want 401", resp.StatusCode)
	}
	challenge := winrmTestAuthToken(t, resp)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("the 401 carries no CHALLENGE: %x", challenge)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, proof, blob := captureTestV2Auth(t, challenge, user, "CORP", "WS20", "Autumn2025!")
	resp = c.do(t, msg)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("AUTHENTICATE got %d, want 401: capture only never accepts a logon", resp.StatusCode)
	}

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("%s::CORP:%s:%s:%s", user, hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "5600" {
		t.Errorf("hashcat_mode is %q, want 5600", rec["hashcat_mode"])
	}
	if rec["_proto"] != proto {
		t.Errorf("_proto is %q, want %s", rec["_proto"], proto)
	}
	if rec["_server"] != addr {
		t.Errorf("_server is %q, want %q", rec["_server"], addr)
	}
	if rec["username"] != user || rec["domain"] != "CORP" || rec["workstation"] != "WS20" {
		t.Errorf("identity fields are %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}
	if rec["ntlm_version"] != "v2" {
		t.Errorf("ntlm_version is %q, want v2", rec["ntlm_version"])
	}
	if !strings.HasPrefix(rec["_host"], "127.0.0.1:") {
		t.Errorf("_host is %q, want the victim address", rec["_host"])
	}
}

func TestWinRMCaptureNTLMv2(t *testing.T) {
	addr, got, _ := winrmTestServer(t)
	winrmTestCapture(t, winrmTestDial(t, addr), got, "winrm", addr, "wsman")
}

func TestWinRMSCaptureNTLMv2(t *testing.T) {
	rw, got := captureTestWriter(t)
	conf := NewConfWinRMS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw
	if err := SpawnWinRMS(conf); err != nil {
		t.Fatalf("SpawnWinRMS failed: %s", err)
	}
	t.Cleanup(conf.Shutdown)

	addr := fmt.Sprintf("127.0.0.1:%d", conf.BindPort)
	winrmTestCapture(t, winrmTestDialTLS(t, addr), got, "winrms", addr, "wsmans")
}

// TestWinRMNegotiateScheme checks the other scheme a WinRM client uses: the
// token wrapped in SPNEGO behind an Authorization: Negotiate header.
func TestWinRMNegotiateScheme(t *testing.T) {
	addr, got, _ := winrmTestServer(t)
	c := winrmTestDial(t, addr)

	send := func(scheme string, token []byte) *http.Response {
		t.Helper()
		var req bytes.Buffer
		fmt.Fprintf(&req, "POST /wsman HTTP/1.1\r\nHost: %s\r\nContent-Length: 0\r\n", addr)
		fmt.Fprintf(&req, "Authorization: %s %s\r\n\r\n", scheme, base64.StdEncoding.EncodeToString(token))
		if _, err := c.conn.Write(req.Bytes()); err != nil {
			t.Fatalf("sending a request: %s", err)
		}
		resp, err := http.ReadResponse(c.br, nil)
		if err != nil {
			t.Fatalf("reading a response: %s", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	resp := send("Negotiate", smbSPNEGONegTokenInit2WithToken(captureTestNegotiate()))
	challenge := winrmTestAuthToken(t, resp)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("the 401 carries no CHALLENGE: %x", challenge)
	}

	msg, _, _ := captureTestV2Auth(t, challenge, "spnego", "CORP", "WS21", "pass")
	send("Negotiate", smbSPNEGONegTokenResp(msg))

	rec := captureTestRecord(t, got)
	if rec["username"] != "spnego" {
		t.Errorf("username is %q, want spnego", rec["username"])
	}
}

// smbSPNEGONegTokenInit2WithToken wraps an NTLMSSP message in a SPNEGO
// negTokenInit, which is how a Negotiate-scheme client delivers its first
// token.
func smbSPNEGONegTokenInit2WithToken(token []byte) []byte {
	mechTypes := smbDER(0x30, smbDER(0x06, smbMechNTLMSSP))
	body := append(smbDER(0xa0, mechTypes), smbDER(0xa2, smbDER(0x04, token))...)
	negTokenInit := smbDER(0x30, body)
	inner := append(smbDER(0x06, smbOIDSPNEGO), smbDER(0xa0, negTokenInit)...)
	return smbDER(0x60, inner)
}

// TestWinRMMalformed throws rubbish at the listener and checks it stays up.
func TestWinRMMalformed(t *testing.T) {
	addr, got, _ := winrmTestServer(t)

	cases := []struct {
		name string
		send string
	}{
		{"not http", "\x00\x01\x02\x03\r\n\r\n"},
		{"empty auth header", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: \r\n\r\n"},
		{"unknown scheme", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abcd\r\n\r\n"},
		{"bad base64", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM !!!!\r\n\r\n"},
		{"short token", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM QUJD\r\n\r\n"},
		{"authenticate with no negotiate", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM " +
			base64.StdEncoding.EncodeToString(ntlmTestAuthMsg("ghost", "CORP", "WS", nil, make([]byte, 24), nil, 0)) +
			"\r\n\r\n"},
		{"challenge where a negotiate belongs", "GET /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM " +
			base64.StdEncoding.EncodeToString(NTLMChallengeMessage(0)) + "\r\n\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %s", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			conn.Write([]byte(tc.send))
			io.Copy(io.Discard, conn)
		})
	}

	select {
	case rec := <-got:
		t.Errorf("malformed input produced a credential: %v", rec)
	default:
	}

	// The listener still serves a real client.
	winrmTestCapture(t, winrmTestDial(t, addr), got, "winrm", addr, "survivor")
}

// TestWinRMDisconnectMidExchange checks the adapter releases victims that
// negotiate and then drop, rather than holding a goroutine for each.
func TestWinRMDisconnectMidExchange(t *testing.T) {
	addr, _, conf := winrmTestServer(t)
	conf.capture.Timeout = 200 * time.Millisecond

	settle(t, 0)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %s", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		c := &winrmTestConn{conn: conn, br: bufio.NewReader(conn), addr: addr}
		c.do(t, captureTestNegotiate())
		conn.Close()
	}

	conf.Shutdown()
	settle(t, before)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines went from %d to %d across 20 abandoned exchanges", before, after)
	}
}

func TestWinRMShutdown(t *testing.T) {
	addr, _, conf := winrmTestServer(t)
	winrmTestDial(t, addr)

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

func TestWinRMSShutdown(t *testing.T) {
	rw, _ := captureTestWriter(t)
	conf := NewConfWinRMS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw
	if err := SpawnWinRMS(conf); err != nil {
		t.Fatalf("SpawnWinRMS failed: %s", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", conf.BindPort)
	start := time.Now()
	conf.Shutdown()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Shutdown took %s", elapsed)
	}
	conf.Shutdown()

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("the port is still accepting connections after Shutdown")
	}
}

func TestWinRMSBadCertificate(t *testing.T) {
	rw, _ := captureTestWriter(t)
	conf := NewConfWinRMS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.TLSCertFile = "/nonexistent/flamingo-test.pem"
	conf.TLSKeyFile = "/nonexistent/flamingo-test.key"
	conf.RecordWriter = rw

	if err := SpawnWinRMS(conf); err == nil {
		conf.Shutdown()
		t.Fatal("a missing certificate was accepted")
	}
}

func TestNewConfWinRM(t *testing.T) {
	conf := NewConfWinRM()
	if conf.BindPort != 5985 {
		t.Errorf("default WinRM port is %d, want 5985", conf.BindPort)
	}
	if conf.BindHost != "[::]" {
		t.Errorf("default host is %q, want [::]", conf.BindHost)
	}

	confs := NewConfWinRMS()
	if confs.BindPort != 5986 {
		t.Errorf("default WinRMS port is %d, want 5986", confs.BindPort)
	}
	if confs.BindHost != "[::]" {
		t.Errorf("default host is %q, want [::]", confs.BindHost)
	}
}
