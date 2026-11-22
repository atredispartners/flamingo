package flamingo

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// httpTestServer spawns an HTTP collector on a free port after letting the
// caller adjust the configuration, and returns its address plus a channel
// receiving captured records.
func httpTestServer(t *testing.T, setup func(*ConfHTTP)) (string, chan map[string]string, *ConfHTTP) {
	t.Helper()

	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %s", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	conf := NewConfHTTP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = port
	conf.AuthMode = "ntlm"
	conf.RecordWriter = rw
	if setup != nil {
		setup(conf)
	}
	if err := SpawnHTTP(conf); err != nil {
		t.Fatalf("spawn http: %s", err)
	}
	t.Cleanup(conf.Shutdown)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, got, conf
}

// httpRawRequest sends one request over a fresh connection and returns the
// parsed response. A connection reset in place of a response — which is how
// the proxy ends a captured exchange — yields a nil response and no error.
func httpRawRequest(t *testing.T, addr string, req string) *http.Response {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write: %s", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil
	}
	return resp
}

func httpWaitRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no record written")
		return nil
	}
}

// httpWaitCredential skips the access records an in-progress challenge writes
// and returns the first captured credential.
func httpWaitCredential(t *testing.T, got chan map[string]string) map[string]string {
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

// TestHTTPWPADServesPAC checks that an opted-in listener hands out a PAC file
// naming the proxy, with the content type a Windows WPAD client expects.
func TestHTTPWPADServesPAC(t *testing.T) {
	addr, got, _ := httpTestServer(t, func(c *ConfHTTP) {
		c.ServeWPAD = true
	})

	for _, path := range []string{"/wpad.dat", "/wpad.da", "/proxy.pac", "/WPAD.DAT"} {
		resp := httpRawRequest(t, addr, fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, addr))
		if resp == nil {
			t.Fatalf("%s: no response", path)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status = %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
			t.Errorf("%s: Content-Type = %q", path, ct)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s: read body: %s", path, err)
		}
		pac := string(body)
		if !strings.Contains(pac, "function FindProxyForURL(url, host)") {
			t.Errorf("%s: PAC has no FindProxyForURL: %q", path, pac)
		}
		// With no override, the proxy is the host the client used plus the
		// conventional proxy port.
		want := fmt.Sprintf("PROXY 127.0.0.1:%d; DIRECT", HTTPProxyPort)
		if !strings.Contains(pac, want) {
			t.Errorf("%s: PAC does not name %q: %q", path, want, pac)
		}
		if !strings.Contains(pac, `return "DIRECT"`) {
			t.Errorf("%s: PAC has no DIRECT fallback for local names: %q", path, pac)
		}

		rec := httpWaitRecord(t, got)
		if rec["wpad"] != "served" {
			t.Errorf("%s: wpad = %q, want served", path, rec["wpad"])
		}
	}
}

// TestHTTPWPADOffByDefault pins the safe default: serving a proxy config is an
// active redirection, so a listener that was not told to do it must not.
func TestHTTPWPADOffByDefault(t *testing.T) {
	if NewConfHTTP().ServeWPAD {
		t.Fatal("ServeWPAD defaults to true")
	}

	addr, _, _ := httpTestServer(t, nil)
	resp := httpRawRequest(t, addr, fmt.Sprintf("GET /wpad.dat HTTP/1.0\r\nHost: %s\r\n\r\n", addr))
	if resp == nil {
		t.Fatal("no response")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "FindProxyForURL") {
		t.Fatalf("a PAC file was served without ServeWPAD: %q", body)
	}
}

// TestHTTPWPADProxyOverride checks the host:port override and the bare-host
// form that takes the configured proxy port.
func TestHTTPWPADProxyOverride(t *testing.T) {
	for _, tc := range []struct {
		proxy string
		port  uint16
		want  string
	}{
		{"10.1.2.3:8080", 0, "PROXY 10.1.2.3:8080; DIRECT"},
		{"10.1.2.3", 0, fmt.Sprintf("PROXY 10.1.2.3:%d; DIRECT", HTTPProxyPort)},
		{"10.1.2.3", 8888, "PROXY 10.1.2.3:8888; DIRECT"},
		{"", 8888, "PROXY 127.0.0.1:8888; DIRECT"},
	} {
		addr, _, _ := httpTestServer(t, func(c *ConfHTTP) {
			c.ServeWPAD = true
			c.WPADProxy = tc.proxy
			c.WPADProxyPort = tc.port
		})
		resp := httpRawRequest(t, addr, fmt.Sprintf("GET /wpad.dat HTTP/1.0\r\nHost: %s\r\n\r\n", addr))
		if resp == nil {
			t.Fatalf("%q/%d: no response", tc.proxy, tc.port)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), tc.want) {
			t.Errorf("%q/%d: PAC does not name %q: %q", tc.proxy, tc.port, tc.want, body)
		}
	}
}

// TestHTTPProxyNTLMCapture walks the 407 exchange and checks the captured
// credential is the same hashcat 5600 line the 401 path produces.
func TestHTTPProxyNTLMCapture(t *testing.T) {
	addr, got, _ := httpTestServer(t, func(c *ConfHTTP) {
		c.ProxyAuth = true
	})

	// No credential at all: the proxy must ask for one.
	resp := httpRawRequest(t, addr, fmt.Sprintf("GET http://example.com/ HTTP/1.0\r\nHost: %s\r\n\r\n", addr))
	if resp == nil {
		t.Fatal("no response to an unauthenticated proxy request")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if hdr := resp.Header.Get("Proxy-Authenticate"); hdr != "NTLM" {
		t.Fatalf("Proxy-Authenticate = %q, want NTLM", hdr)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Error("a proxy must not send WWW-Authenticate")
	}
	<-got // the access record for the unauthenticated request

	// NEGOTIATE: the proxy must answer with a CHALLENGE carrying the
	// configured server challenge.
	neg := base64.StdEncoding.EncodeToString(smtpNTLMNegotiate())
	resp = httpRawRequest(t, addr, fmt.Sprintf(
		"GET http://example.com/ HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\n\r\n", addr, neg))
	if resp == nil {
		t.Fatal("no response to a NEGOTIATE")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	hdr := resp.Header.Get("Proxy-Authenticate")
	if !strings.HasPrefix(hdr, "NTLM ") {
		t.Fatalf("Proxy-Authenticate = %q, want an NTLM challenge", hdr)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "NTLM "))
	if err != nil {
		t.Fatalf("challenge is not base64: %s", err)
	}
	if NTLMMessageType(raw) != NTLMTypeChallenge {
		t.Fatalf("message type = %d, want CHALLENGE", NTLMMessageType(raw))
	}

	// AUTHENTICATE: the credential is recorded, and the exchange is ended
	// rather than proxied.
	proof := make([]byte, 16)
	for i := range proof {
		proof[i] = byte(0xc0 + i)
	}
	blob := append([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}, make([]byte, 20)...)
	msg := base64.StdEncoding.EncodeToString(smtpNTLMAuthenticate("victim", "CORP", "WS01", proof, blob))
	httpRawRequest(t, addr, fmt.Sprintf(
		"GET http://example.com/ HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: NTLM %s\r\n\r\n", addr, msg))

	rec := httpWaitCredential(t, got)
	if rec["_type"] != "credential" {
		t.Fatalf("_type = %q, want credential", rec["_type"])
	}
	if rec["_proto"] != "http-proxy" {
		t.Errorf("_proto = %q, want http-proxy", rec["_proto"])
	}
	if rec["username"] != "victim" {
		t.Errorf("username = %q, want victim", rec["username"])
	}
	want := fmt.Sprintf("victim::CORP:%s:%s:%s",
		hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof),
		hex.EncodeToString(blob))
	if rec["hashcat"] != want {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], want)
	}
}

// TestHTTPProxyBasicCapture checks the Basic half of the 407 exchange.
func TestHTTPProxyBasicCapture(t *testing.T) {
	addr, got, _ := httpTestServer(t, func(c *ConfHTTP) {
		c.ProxyAuth = true
		c.AuthMode = "basic"
		c.BasicRealm = "Corporate Proxy"
	})

	resp := httpRawRequest(t, addr, fmt.Sprintf("GET http://example.com/ HTTP/1.0\r\nHost: %s\r\n\r\n", addr))
	if resp == nil {
		t.Fatal("no response to an unauthenticated proxy request")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if hdr := resp.Header.Get("Proxy-Authenticate"); hdr != `Basic realm="Corporate Proxy"` {
		t.Fatalf("Proxy-Authenticate = %q", hdr)
	}
	<-got

	cred := base64.StdEncoding.EncodeToString([]byte("CORP\\victim:Summer2026!"))
	httpRawRequest(t, addr, fmt.Sprintf(
		"GET http://example.com/ HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", addr, cred))

	rec := httpWaitCredential(t, got)
	if rec["_type"] != "credential" || rec["_proto"] != "http-proxy" {
		t.Fatalf("record = %v", rec)
	}
	if rec["username"] != `CORP\victim` || rec["password"] != "Summer2026!" {
		t.Errorf("username/password = %q/%q", rec["username"], rec["password"])
	}
	if rec["method"] != "basic" {
		t.Errorf("method = %q, want basic", rec["method"])
	}
}

// TestHTTPProxyChallengesEveryMethod checks that CONNECT and POST, which the
// origin-server path answers with 404, are challenged by the proxy path.
func TestHTTPProxyChallengesEveryMethod(t *testing.T) {
	addr, _, _ := httpTestServer(t, func(c *ConfHTTP) {
		c.ProxyAuth = true
	})

	for _, req := range []string{
		fmt.Sprintf("CONNECT example.com:443 HTTP/1.1\r\nHost: %s\r\n\r\n", addr),
		fmt.Sprintf("POST http://example.com/ HTTP/1.0\r\nHost: %s\r\nContent-Length: 0\r\n\r\n", addr),
	} {
		resp := httpRawRequest(t, addr, req)
		if resp == nil {
			t.Fatalf("%.20q: no response", req)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("%.20q: status = %d, want 407", req, resp.StatusCode)
		}
	}
}

// TestHTTPProxyMalformedAuth makes sure junk in Proxy-Authorization neither
// panics the handler nor records a credential.
func TestHTTPProxyMalformedAuth(t *testing.T) {
	addr, got, _ := httpTestServer(t, func(c *ConfHTTP) {
		c.ProxyAuth = true
	})

	for _, auth := range []string{
		"NTLM !!!not-base64!!!",
		"NTLM " + base64.StdEncoding.EncodeToString([]byte("NTLMSSP\x00\x03\x00\x00\x00")),
		"NTLM " + base64.StdEncoding.EncodeToString(make([]byte, 200)),
		"Negotiate " + base64.StdEncoding.EncodeToString([]byte{0x60, 0x01, 0x02}),
		"Kerberos abcd",
		"NTLM",
	} {
		resp := httpRawRequest(t, addr, fmt.Sprintf(
			"GET http://example.com/ HTTP/1.0\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", addr, auth))
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Drain whatever was recorded; none of it may be a credential.
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case rec := <-got:
			if rec["_type"] == "credential" {
				t.Fatalf("junk auth header produced a credential: %v", rec)
			}
		case <-deadline:
			return
		}
	}
}
