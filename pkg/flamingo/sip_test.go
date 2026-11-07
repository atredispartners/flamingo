package flamingo

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// sipTestServer spawns a SIP collector on a free port and returns the
// address plus a channel that receives captured credential records.
func sipTestServer(t *testing.T) (string, chan map[string]string, *ConfSIP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfSIP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnSIP(conf); err != nil {
		t.Fatalf("SpawnSIP failed: %s", err)
	}
	return conf.listener.LocalAddr().String(), got, conf
}

// sipExchange sends one datagram and returns the reply, or an empty string
// when none arrives within the timeout.
func sipExchange(t *testing.T, addr string, payload string, timeout time.Duration) string {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	buff := make([]byte, 4096)
	n, err := conn.Read(buff)
	if err != nil {
		return ""
	}
	return string(buff[:n])
}

// sipWaitCred waits for a captured credential record
func sipWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// sipNoCred fails the test if a record arrives within a short window
func sipNoCred(t *testing.T, got chan map[string]string) {
	t.Helper()
	select {
	case rec := <-got:
		t.Errorf("unexpected record %v", rec)
	case <-time.After(200 * time.Millisecond):
	}
}

// sipRequestText builds a request datagram with the standard dialog
// headers plus any extra header lines.
func sipRequestText(method string, uri string, extra string) string {
	return fmt.Sprintf("%s %s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n"+
		"From: <sip:alice@example.com>;tag=1928301774\r\n"+
		"To: <sip:alice@example.com>\r\n"+
		"Call-ID: a84b4c76e66710@192.0.2.10\r\n"+
		"CSeq: 1 %s\r\n"+
		"User-Agent: flamingo-test/1.0\r\n"+
		"%s"+
		"Content-Length: 0\r\n\r\n", method, uri, method, extra)
}

// sipMD5 returns the lowercase hex MD5 of a string
func sipMD5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sipDigestResponse computes an RFC 2617 Digest response. With an empty qop
// the RFC 2069 form (no nc or cnonce) is used.
func sipDigestResponse(username, realm, password, method, uri, nonce, nc, cnonce, qop string) string {
	ha1 := sipMD5(username + ":" + realm + ":" + password)
	ha2 := sipMD5(method + ":" + uri)
	if qop == "" {
		return sipMD5(ha1 + ":" + nonce + ":" + ha2)
	}
	return sipMD5(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// TestSIPChallenge verifies an unauthenticated REGISTER is challenged with
// the fixed nonce and produces no record.
func TestSIPChallenge(t *testing.T) {
	addr, got, conf := sipTestServer(t)
	defer conf.Shutdown()

	reply := sipExchange(t, addr, sipRequestText("REGISTER", "sip:example.com", ""), 5*time.Second)
	if !strings.HasPrefix(reply, "SIP/2.0 401 Unauthorized\r\n") {
		t.Fatalf("expected 401, got %q", reply)
	}
	want := fmt.Sprintf("WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"%s\", algorithm=MD5\r\n", SIPNonce)
	if !strings.Contains(reply, want) {
		t.Errorf("challenge missing fixed nonce: %q", reply)
	}
	for _, h := range []string{"Via: SIP/2.0/UDP 192.0.2.10", "From: <sip:alice@example.com>;tag=1928301774", "Call-ID: a84b4c76e66710@192.0.2.10", "CSeq: 1 REGISTER", "Server: Asterisk PBX 18.9.0"} {
		if !strings.Contains(reply, h) {
			t.Errorf("reply missing %q: %q", h, reply)
		}
	}
	if !strings.Contains(reply, "To: <sip:alice@example.com>;tag=") {
		t.Errorf("reply To header is not tagged: %q", reply)
	}
	sipNoCred(t, got)
}

// TestSIPDigestCapture verifies Digest credentials are refused, recorded
// with the fields needed to recompute the response, and formatted for
// hashcat mode 11400.
func TestSIPDigestCapture(t *testing.T) {
	const (
		username = "alice"
		password = "hunter2"
		realm    = "asterisk"
		method   = "REGISTER"
		uri      = "sip:example.com:5060;transport=udp"
	)

	cases := []struct {
		name   string
		qop    string
		nc     string
		cnonce string
		header string
	}{
		{name: "qop-auth", qop: "auth", nc: "00000001", cnonce: "0a4f113b", header: "Authorization"},
		{name: "rfc2069", header: "Proxy-Authorization"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, got, conf := sipTestServer(t)
			defer conf.Shutdown()

			response := sipDigestResponse(username, realm, password, method, uri, SIPNonce, tc.nc, tc.cnonce, tc.qop)
			auth := fmt.Sprintf("%s: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=MD5",
				tc.header, username, realm, SIPNonce, uri, response)
			if tc.qop != "" {
				auth += fmt.Sprintf(", qop=%s, nc=%s, cnonce=\"%s\"", tc.qop, tc.nc, tc.cnonce)
			}

			reply := sipExchange(t, addr, sipRequestText(method, "sip:example.com", auth+"\r\n"), 5*time.Second)
			if !strings.HasPrefix(reply, "SIP/2.0 403 Forbidden\r\n") {
				t.Fatalf("expected 403, got %q", reply)
			}

			rec := sipWaitCred(t, got)
			want := map[string]string{
				"_type":      "credential",
				"_proto":     "sip",
				"username":   username,
				"realm":      realm,
				"nonce":      SIPNonce,
				"uri":        uri,
				"response":   response,
				"method":     method,
				"algorithm":  "MD5",
				"user_agent": "flamingo-test/1.0",
				"from":       "<sip:alice@example.com>;tag=1928301774",
				"to":         "<sip:alice@example.com>",
				"call_id":    "a84b4c76e66710@192.0.2.10",
				"qop":        tc.qop,
				"nc":         tc.nc,
				"cnonce":     tc.cnonce,
			}
			for k, v := range want {
				if rec[k] != v {
					t.Errorf("%s = %q, want %q", k, rec[k], v)
				}
			}
			if tc.qop == "" {
				for _, k := range []string{"qop", "nc", "cnonce"} {
					if _, ok := rec[k]; ok {
						t.Errorf("%s should be absent without qop", k)
					}
				}
			}
			if !strings.HasPrefix(rec["_server"], "127.0.0.1:") {
				t.Errorf("_server = %q", rec["_server"])
			}

			// Recompute the digest from the record alone to confirm the
			// captured fields are consistent with the known password.
			recomputed := sipDigestResponse(rec["username"], rec["realm"], password, rec["method"], rec["uri"], rec["nonce"], rec["nc"], rec["cnonce"], rec["qop"])
			if recomputed != rec["response"] {
				t.Errorf("recomputed digest %q != recorded %q", recomputed, rec["response"])
			}

			// hashcat 11400: $sip$*URI_server*URI_client*username*realm*method*URI_prefix*URI_resource*URI_suffix*nonce*cnonce*nc*qop*algorithm*response
			wantHash := fmt.Sprintf("$sip$***%s*%s*%s*sip*example.com*5060;transport=udp*%s*%s*%s*%s*MD5*%s",
				username, realm, method, SIPNonce, tc.cnonce, tc.nc, tc.qop, response)
			if rec["hashcat"] != wantHash {
				t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantHash)
			}
			parts := strings.Split(rec["hashcat"], "*")
			if len(parts) != 15 || parts[0] != "$sip$" {
				t.Errorf("hashcat has %d fields, want 15: %q", len(parts), rec["hashcat"])
			}
			// hashcat rebuilds the URI from prefix:resource:suffix; make sure
			// the split is lossless so HA2 matches.
			rebuilt := parts[6] + ":" + parts[7]
			if parts[8] != "" {
				rebuilt += ":" + parts[8]
			}
			if rebuilt != uri {
				t.Errorf("hashcat URI rebuilt as %q, want %q", rebuilt, uri)
			}
		})
	}
}

// TestSIPOptions verifies OPTIONS gets a 200 OK and produces no record
func TestSIPOptions(t *testing.T) {
	addr, got, conf := sipTestServer(t)
	defer conf.Shutdown()

	reply := sipExchange(t, addr, sipRequestText("OPTIONS", "sip:example.com", ""), 5*time.Second)
	if !strings.HasPrefix(reply, "SIP/2.0 200 OK\r\n") {
		t.Fatalf("expected 200, got %q", reply)
	}
	for _, h := range []string{"Allow: INVITE, ACK", "Server: Asterisk PBX 18.9.0", "CSeq: 1 OPTIONS", "Content-Length: 0"} {
		if !strings.Contains(reply, h) {
			t.Errorf("reply missing %q: %q", h, reply)
		}
	}
	if strings.Contains(reply, "WWW-Authenticate") {
		t.Errorf("OPTIONS reply should not challenge: %q", reply)
	}
	sipNoCred(t, got)
}

// TestSIPInvalid verifies garbage, responses and ACK produce no reply and
// leave the server working.
func TestSIPInvalid(t *testing.T) {
	addr, got, conf := sipTestServer(t)
	defer conf.Shutdown()

	for _, payload := range []string{
		"\x00\x01\x02\xff\xfe garbage\r\n\r\n",
		"",
		"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.10\r\n\r\n",
		sipRequestText("ACK", "sip:example.com", ""),
	} {
		if reply := sipExchange(t, addr, payload, 300*time.Millisecond); reply != "" {
			t.Errorf("unexpected reply to %q: %q", payload, reply)
		}
	}
	// A Digest header with no parameters is refused but not recorded.
	reply := sipExchange(t, addr, "REGISTER sip:example.com SIP/2.0\r\nAuthorization: Digest\r\n\r\n", 5*time.Second)
	if !strings.HasPrefix(reply, "SIP/2.0 403 Forbidden\r\n") {
		t.Errorf("expected 403 for empty Digest, got %q", reply)
	}
	sipNoCred(t, got)

	reply = sipExchange(t, addr, sipRequestText("OPTIONS", "sip:example.com", ""), 5*time.Second)
	if !strings.HasPrefix(reply, "SIP/2.0 200 OK\r\n") {
		t.Fatalf("server not responding after invalid input: %q", reply)
	}
}
