package flamingo

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// httpNTLMTestServer spawns an HTTP collector on a free port and returns its
// address plus a channel receiving captured records.
func httpNTLMTestServer(t *testing.T) (string, chan map[string]string, *ConfHTTP) {
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

// httpNTLMGet issues a GET carrying the given Authorization header value and
// returns the response.
func httpNTLMGet(t *testing.T, addr, auth string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	if err != nil {
		t.Fatalf("new request: %s", err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %s", err)
	}
	return resp
}

// TestHTTPNTLMChallengeMatchesConf is the regression guard for the coupling
// that previously existed between a frozen base64 CHALLENGE blob and the
// challenge NTLMHashcat writes into captured lines. The challenge on the wire
// must be the one the recorded hash is cracked against, whatever NTLMConf says.
func TestHTTPNTLMChallengeMatchesConf(t *testing.T) {
	addr, _, _ := httpNTLMTestServer(t)

	resp := httpNTLMGet(t, addr, "NTLM "+base64.StdEncoding.EncodeToString(smtpNTLMNegotiate()))
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	hdr := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(hdr, "NTLM ") {
		t.Fatalf("WWW-Authenticate = %q, want an NTLM challenge", hdr)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "NTLM "))
	if err != nil {
		t.Fatalf("challenge is not base64: %s", err)
	}
	if NTLMMessageType(raw) != NTLMTypeChallenge {
		t.Fatalf("message type = %d, want %d", NTLMMessageType(raw), NTLMTypeChallenge)
	}
	if len(raw) < 32 {
		t.Fatalf("challenge is %d bytes, too short", len(raw))
	}
	if !bytes.Equal(raw[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("server challenge = %x, want %x", raw[24:32], NTLMConf.Challenge)
	}
}

// TestHTTPNTLMRecordsAuthenticate verifies an AUTHENTICATE is recorded as a
// hashcat 5600 line built from the same challenge the server sent.
func TestHTTPNTLMRecordsAuthenticate(t *testing.T) {
	addr, got, _ := httpNTLMTestServer(t)

	proof := make([]byte, 16)
	for i := range proof {
		proof[i] = byte(0xb0 + i)
	}
	// The blob must take the NT response past 24 bytes, or it is by definition
	// an NTLMv1 response and gets formatted as hashcat 5500 instead.
	blob := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}
	blob = append(blob, make([]byte, 20)...)

	msg := smtpNTLMAuthenticate("victim", "CORP", "WS01", proof, blob)
	resp := httpNTLMGet(t, addr, "NTLM "+base64.StdEncoding.EncodeToString(msg))
	defer resp.Body.Close()

	select {
	case rec := <-got:
		if rec["username"] != "victim" {
			t.Fatalf("username = %q, want victim", rec["username"])
		}
		want := fmt.Sprintf("victim::CORP:%s:%s:%s",
			hex.EncodeToString(NTLMConf.Challenge[:]),
			hex.EncodeToString(proof),
			hex.EncodeToString(blob))
		if rec["hashcat"] != want {
			t.Fatalf("hashcat = %q, want %q", rec["hashcat"], want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no credential recorded")
	}
}
