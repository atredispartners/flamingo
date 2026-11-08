package flamingo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/runZeroInc/excrypto/crypto/ssl2"
	ltls "github.com/runZeroInc/excrypto/crypto/ssl3/tls"
)

// legacyTestECDSACert returns a self-signed ECDSA key pair like the one
// generateTLSCertificate creates.
func legacyTestECDSACert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

// legacyEchoServer listens with listenTLS and echoes one line per connection in
// upper case.
func legacyEchoServer(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := legacyTestECDSACert(t)
	cfg, err := newServerTLSConfig(certPEM, keyPEM, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	l, err := listenTLS("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 5)
				if _, err := io.ReadFull(c, buf); err == nil {
					c.Write(bytes.ToUpper(buf))
				}
			}()
		}
	}()
	return l.Addr().String()
}

func legacyRoundTrip(t *testing.T, rw io.ReadWriter) {
	t.Helper()
	if _, err := rw.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rw, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PING\n" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestTLSLegacySSLv2(t *testing.T) {
	addr := legacyEchoServer(t)
	sc, _, err := ssl2.DialAndHandshake(addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	legacyRoundTrip(t, sc)
}

func TestTLSLegacyStacks(t *testing.T) {
	addr := legacyEchoServer(t)
	cases := []struct {
		name    string
		version uint16
		suite   uint16
	}{
		{"ssl3-rc4", ltls.VersionSSL30, ltls.TLS_RSA_WITH_RC4_128_SHA},
		{"tls10-export", ltls.VersionTLS10, ltls.TLS_RSA_EXPORT_WITH_RC4_40_MD5},
		{"tls11-des", ltls.VersionTLS11, ltls.TLS_DHE_RSA_WITH_DES_CBC_SHA},
		{"tls12-dhe", ltls.VersionTLS12, ltls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nc, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			cc := ltls.Client(nc, &ltls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tc.version,
				MaxVersion:         tc.version,
				CipherSuites:       []uint16{tc.suite},
				ForceSuites:        true,
			})
			if err := cc.Handshake(); err != nil {
				t.Fatal(err)
			}
			if st := cc.ConnectionState(); st.Version != tc.version || st.CipherSuite != tc.suite {
				t.Fatalf("negotiated version %#x suite %#x", st.Version, st.CipherSuite)
			}
			legacyRoundTrip(t, cc)
		})
	}
}

func TestTLSLegacyCertificateType(t *testing.T) {
	addr := legacyEchoServer(t)
	cases := []struct {
		name    string
		cfg     *tls.Config
		wantRSA bool
	}{
		{"tls13-ecdsa", &tls.Config{MinVersion: tls.VersionTLS13}, false},
		{"tls12-rsa-only", &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}, true},
		{"tls10-rsa-kex", &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.InsecureSkipVerify = true
			cc, err := tls.Dial("tcp", addr, tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			legacyRoundTrip(t, cc)
			_, isRSA := cc.ConnectionState().PeerCertificates[0].PublicKey.(*rsa.PublicKey)
			if isRSA != tc.wantRSA {
				t.Fatalf("server key %T, want RSA=%v", cc.ConnectionState().PeerCertificates[0].PublicKey, tc.wantRSA)
			}
		})
	}
}

func TestTLSParseSSLv2Hello(t *testing.T) {
	// A per-cipher SSL 2.0 probe (IDEA-128-CBC-MD5) and a compatible hello
	// offering TLS 1.0 with one TLS suite and one SSL 2.0 kind.
	probe := append([]byte("\x80\x1c\x01\x00\x02\x00\x03\x00\x00\x00\x10\x05\x00\x80"), bytes.Repeat([]byte{0x41}, 16)...)
	compat := append([]byte("\x80\x1f\x01\x03\x01\x00\x06\x00\x00\x00\x10\x00\x00\x2f\x01\x00\x80"), bytes.Repeat([]byte{0x42}, 16)...)
	if n := tlsHelloLength(probe[:9]); n != len(probe) {
		t.Fatalf("length = %d, want %d", n, len(probe))
	}
	h, ok := tlsParseHello(probe)
	if !ok || !h.sslv2 || h.version != 0x0002 || len(h.ciphers) != 0 {
		t.Fatalf("probe = %+v", h)
	}
	h, ok = tlsParseHello(compat)
	if !ok || !h.sslv2 || h.version != tls.VersionTLS10 || len(h.ciphers) != 1 || h.ciphers[0] != 0x002f {
		t.Fatalf("compat = %+v", h)
	}
	for _, b := range [][]byte{[]byte("GET / HTTP/1.1\r\n"), {0x80, 0x10, 0x02, 0x00, 0x02}, {0x80, 0x10, 0x01, 0x05, 0x00}} {
		if tlsIsSSLv2Hello(b) {
			t.Errorf("%q detected as SSL 2.0", b)
		}
	}
}
