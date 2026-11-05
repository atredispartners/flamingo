package flamingo

import (
	"crypto/des"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

// vncKey derives the DES key the way a real VNC client does: the bits of
// each password byte are reversed, and the key is zero-padded to 8 bytes.
func vncKey(pw string) []byte {
	key := make([]byte, 8)
	for i := 0; i < 8; i++ {
		var b byte
		if i < len(pw) {
			b = pw[i]
		}
		var r byte
		for j := 0; j < 8; j++ {
			r = (r << 1) | (b & 1)
			b >>= 1
		}
		key[i] = r
	}
	return key
}

// vncEncrypt encrypts the 16-byte challenge with the password-derived key,
// matching what a VNC client sends as its authentication response.
func vncEncrypt(pw string, challenge []byte) []byte {
	block, err := des.NewCipher(vncKey(pw))
	if err != nil {
		panic(err)
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out
}

// TestVNCCapture drives the collector with a real RFB 3.8 client exchange
// and verifies the captured response is the genuine, crackable artifact.
func TestVNCCapture(t *testing.T) {
	const secret = "s3cr3t" // under 8 chars, exercises the zero-pad path

	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfVNC()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0 // let the OS pick a free port
	conf.RecordWriter = rw

	if err := SpawnVNC(conf); err != nil {
		t.Fatalf("SpawnVNC failed: %s", err)
	}
	defer conf.Shutdown()

	addr := conf.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// RFB 3.8 client handshake.
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		t.Fatalf("read server version: %s", err)
	}
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatalf("write client version: %s", err)
	}

	cnt := make([]byte, 1)
	if _, err := io.ReadFull(conn, cnt); err != nil {
		t.Fatalf("read sec type count: %s", err)
	}
	types := make([]byte, int(cnt[0]))
	if _, err := io.ReadFull(conn, types); err != nil {
		t.Fatalf("read sec types: %s", err)
	}
	if _, err := conn.Write([]byte{vncSecTypeVNCAuth}); err != nil {
		t.Fatalf("select sec type: %s", err)
	}

	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		t.Fatalf("read challenge: %s", err)
	}

	resp := vncEncrypt(secret, challenge)
	if _, err := conn.Write(resp); err != nil {
		t.Fatalf("write response: %s", err)
	}

	var rec map[string]string
	select {
	case rec = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no credential record captured")
	}

	if rec["_type"] != "credential" {
		t.Errorf("expected credential record, got %q", rec["_type"])
	}
	if rec["response"] != hex.EncodeToString(resp) {
		t.Errorf("captured response %q != sent response %q", rec["response"], hex.EncodeToString(resp))
	}

	// The captured response must decrypt/crack back to the real password.
	if hex.EncodeToString(vncEncrypt(secret, challenge)) != rec["response"] {
		t.Error("captured artifact does not recover the known password")
	}

	wantJohn := "$vnc$*" + rec["challenge"] + "*" + rec["response"]
	if rec["john"] != wantJohn {
		t.Errorf("john line %q != expected %q", rec["john"], wantJohn)
	}
}

// TestVNCParseMinor checks version parsing, including the 3.3 fallback.
func TestVNCParseMinor(t *testing.T) {
	cases := map[string]int{
		"RFB 003.008\n":           8,
		"RFB 003.007\n":           7,
		"RFB 003.003\n":           3,
		"garbage\x00\x00\x00\x00": 3,
	}
	for in, want := range cases {
		if got := vncParseMinor([]byte(in)); got != want {
			t.Errorf("vncParseMinor(%q) = %d, want %d", in, got, want)
		}
	}
}
