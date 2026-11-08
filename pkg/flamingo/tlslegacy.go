package flamingo

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"

	exrsa "github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/ssl2"
	ltls "github.com/runZeroInc/excrypto/crypto/ssl3/tls"
)

// tlsMaxHello caps how much of a ClientHello is buffered for parsing.
const tlsMaxHello = 32 << 10

// tlsStdSuiteIDs lists every cipher suite the standard library implements,
// insecure ones included, so clients offering only RSA key exchange, 3DES or RC4
// still connect.
var tlsStdSuiteIDs, tlsStdSuites = func() ([]uint16, map[uint16]bool) {
	var ids []uint16
	set := map[uint16]bool{}
	for _, list := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, s := range list {
			ids = append(ids, s.ID)
			set[s.ID] = true
		}
	}
	return ids, set
}()

// tlsLegacySuiteIDs lists the RSA-authenticated suites offered by the legacy
// stack, including the export and single-DES suites the standard library dropped.
var tlsLegacySuiteIDs = []uint16{
	ltls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	ltls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	ltls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	ltls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	ltls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	ltls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	ltls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	ltls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	ltls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	ltls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	ltls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
	ltls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
	ltls.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	ltls.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	ltls.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	ltls.TLS_DHE_RSA_WITH_DES_CBC_SHA,
	ltls.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	ltls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	ltls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	ltls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	ltls.TLS_RSA_WITH_AES_256_CBC_SHA256,
	ltls.TLS_RSA_WITH_AES_128_CBC_SHA,
	ltls.TLS_RSA_WITH_AES_256_CBC_SHA,
	ltls.TLS_RSA_WITH_RC4_128_SHA,
	ltls.TLS_RSA_WITH_RC4_128_MD5,
	ltls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	ltls.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
	ltls.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
	ltls.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
}

// tlsRSACert is one RSA certificate in the forms each TLS stack needs.
type tlsRSACert struct {
	std    tls.Certificate
	legacy ltls.Certificate
	der    []byte
	key    *exrsa.PrivateKey
}

var (
	// tlsRSACerts caches the RSA certificate for each configured leaf, keyed by
	// the leaf's DER bytes.
	tlsRSACerts sync.Map
	tlsRSAMu    sync.Mutex

	tlsExportOnce sync.Once
	tlsExportKey  *exrsa.PrivateKey
)

// newServerTLSConfig builds a server TLS configuration from a PEM key pair.
// TLS 1.0 and every suite the standard library implements are enabled, and a
// client that cannot use an ECDSA certificate gets an RSA one with the same
// names.
func newServerTLSConfig(certPEM, keyPEM, serverName string) (*tls.Config, error) {
	kp, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{kp},
		MinVersion:   tls.VersionTLS10,
		CipherSuites: tlsStdSuiteIDs,
	}
	// GetConfigForClient runs for every hello; GetCertificate would not run for a
	// client without SNI while Certificates is set.
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if h.SupportsCertificate(&kp) == nil {
			return nil, nil
		}
		rc, err := tlsRSAFor(kp)
		if err != nil {
			return nil, nil
		}
		c := cfg.Clone()
		c.Certificates = []tls.Certificate{rc.std}
		c.GetConfigForClient = nil
		return c, nil
	}
	return cfg, nil
}

// tlsRSAFor returns an RSA certificate for kp: kp itself when its key is RSA,
// otherwise a self-signed RSA certificate with the leaf's subject and names,
// created on first use.
func tlsRSAFor(kp tls.Certificate) (*tlsRSACert, error) {
	if len(kp.Certificate) == 0 {
		return nil, errors.New("tls: no certificate configured")
	}
	id := string(kp.Certificate[0])
	if v, ok := tlsRSACerts.Load(id); ok {
		return v.(*tlsRSACert), nil
	}
	tlsRSAMu.Lock()
	defer tlsRSAMu.Unlock()
	if v, ok := tlsRSACerts.Load(id); ok {
		return v.(*tlsRSACert), nil
	}
	var certPEM, keyPEM []byte
	if key, ok := kp.PrivateKey.(*rsa.PrivateKey); ok {
		for _, der := range kp.Certificate {
			certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	} else {
		leaf, err := x509.ParseCertificate(kp.Certificate[0])
		if err != nil {
			return nil, err
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               leaf.Subject,
			DNSNames:              leaf.DNSNames,
			IPAddresses:           leaf.IPAddresses,
			NotBefore:             leaf.NotBefore,
			NotAfter:              leaf.NotAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	std, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leg, err := ltls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	key, ok := leg.PrivateKey.(*exrsa.PrivateKey)
	if !ok {
		return nil, errors.New("tls: RSA certificate key is not RSA")
	}
	rc := &tlsRSACert{std: std, legacy: leg, der: leg.Certificate[0], key: key}
	tlsRSACerts.Store(id, rc)
	return rc, nil
}

// tlsExportRSAKey returns the 512-bit RSA key used for export key exchange,
// generated once.
func tlsExportRSAKey() *exrsa.PrivateKey {
	tlsExportOnce.Do(func() {
		tlsExportKey, _ = exrsa.GenerateKey(rand.Reader, 512)
	})
	return tlsExportKey
}

// tlsHello holds the ClientHello fields used to pick a TLS stack.
type tlsHello struct {
	version  uint16
	versions []uint16
	ciphers  []uint16
	sni      string
	sslv2    bool
}

// tlsIsSSLv2Hello reports whether b (at least 5 bytes) starts an SSL 2.0 format
// CLIENT-HELLO: a 2-byte record header with the high bit set, message type 1,
// and a version of SSL 2.0 or SSL 3.0 and later.
func tlsIsSSLv2Hello(b []byte) bool {
	if len(b) < 5 || b[0]&0x80 == 0 || b[2] != 0x01 {
		return false
	}
	return b[3] == 0x00 && b[4] == 0x02 || b[3] == 0x03 && b[4] <= 0x04
}

// tlsHelloLength returns the byte length of the records holding the
// ClientHello, given at least its first 9 bytes, or 0 when b is neither a TLS
// handshake nor an SSL 2.0 CLIENT-HELLO.
func tlsHelloLength(b []byte) int {
	if tlsIsSSLv2Hello(b) {
		return 2 + (int(b[0]&0x7f)<<8 | int(b[1]))
	}
	if len(b) < 9 || b[0] != 0x16 || b[5] != 0x01 {
		return 0
	}
	hsLen := int(b[6])<<16 | int(b[7])<<8 | int(b[8])
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if hsLen+4 <= recLen {
		return 5 + recLen
	}
	// The hello spans several records; count one 5-byte header per 16 KB record.
	need := hsLen + 4
	return need + 5*((need+16383)/16384)
}

// tlsParseHello parses an SSL 2.0 CLIENT-HELLO record or the TLS records
// holding a ClientHello, keeping the version, cipher suites and server name.
func tlsParseHello(rec []byte) (*tlsHello, bool) {
	if tlsIsSSLv2Hello(rec) {
		n := int(rec[0]&0x7f)<<8 | int(rec[1])
		if len(rec) < 2+n || n < 9 {
			return nil, false
		}
		body := rec[3 : 2+n]
		h := &tlsHello{sslv2: true, version: binary.BigEndian.Uint16(body)}
		csLen := int(binary.BigEndian.Uint16(body[2:]))
		if 8+csLen > len(body) {
			return nil, false
		}
		for i := 8; i+2 < 8+csLen; i += 3 {
			if body[i] == 0 {
				h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(body[i+1:]))
			}
		}
		return h, true
	}
	var hs []byte
	for len(rec) >= 5 && rec[0] == 0x16 {
		n := int(binary.BigEndian.Uint16(rec[3:5]))
		if len(rec) < 5+n {
			hs = append(hs, rec[5:]...)
			break
		}
		hs = append(hs, rec[5:5+n]...)
		rec = rec[5+n:]
	}
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, false
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return nil, false
	}
	b := hs[4 : 4+n]
	take := func(k int) []byte {
		if k < 0 || len(b) < k {
			b = nil
			return nil
		}
		v := b[:k]
		b = b[k:]
		return v
	}
	vec8 := func() []byte {
		if len(b) < 1 {
			return nil
		}
		return take(int(take(1)[0]))
	}
	vec16 := func() []byte {
		if len(b) < 2 {
			return nil
		}
		return take(int(binary.BigEndian.Uint16(take(2))))
	}
	if len(b) < 34 {
		return nil, false
	}
	h := &tlsHello{version: binary.BigEndian.Uint16(take(2))}
	take(32) // random
	vec8()   // session id
	cs := vec16()
	for i := 0; i+1 < len(cs); i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(cs[i:]))
	}
	vec8() // compression
	exts := vec16()
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts)
		l := int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+l {
			break
		}
		data := exts[4 : 4+l]
		exts = exts[4+l:]
		switch typ {
		case 0: // server_name: list length, then type, name length, name
			if len(data) >= 5 && data[2] == 0 {
				if nl := int(binary.BigEndian.Uint16(data[3:])); 5+nl <= len(data) {
					h.sni = string(data[5 : 5+nl])
				}
			}
		case 43: // supported_versions
			if len(data) >= 1 && 1+int(data[0]) <= len(data) {
				for i := 1; i+1 < 1+int(data[0]); i += 2 {
					h.versions = append(h.versions, binary.BigEndian.Uint16(data[i:]))
				}
			}
		}
	}
	return h, true
}

// tlsNeedsLegacy reports whether the standard library cannot serve h: the
// client's highest non-GREASE version is below TLS 1.0, or none of its suites is
// implemented there.
func tlsNeedsLegacy(h *tlsHello) bool {
	v := h.version
	for _, x := range h.versions {
		if x&0x0f0f != 0x0a0a && x > v {
			v = x
		}
	}
	if v < tls.VersionTLS10 {
		return true
	}
	for _, id := range h.ciphers {
		if tlsStdSuites[id] {
			return false
		}
	}
	return true
}

// tlsReplayConn reads through the buffered reader that holds the peeked
// ClientHello.
type tlsReplayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *tlsReplayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// tlsUpgradedConn is a terminated SSL or TLS session over its raw connection.
type tlsUpgradedConn struct {
	net.Conn
	rw interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
	}
}

func (c *tlsUpgradedConn) Read(p []byte) (int, error)  { return c.rw.Read(p) }
func (c *tlsUpgradedConn) Write(p []byte) (int, error) { return c.rw.Write(p) }

// handshakeTLS terminates TLS on conn with cfg. SSL 2.0 hellos and hellos the
// standard library cannot serve (SSL 3.0, or no suite in common) use the
// excrypto legacy stacks with the RSA certificate for cfg's key pair. It
// returns the connection carrying plaintext.
func handshakeTLS(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	br := bufio.NewReaderSize(conn, tlsMaxHello)
	rc := &tlsReplayConn{Conn: conn, r: br}
	var hello *tlsHello
	if head, err := br.Peek(9); err == nil {
		if n := tlsHelloLength(head); n > 0 {
			raw, _ := br.Peek(min(n, tlsMaxHello))
			hello, _ = tlsParseHello(raw)
		}
	}
	if hello != nil && (hello.sslv2 || tlsNeedsLegacy(hello)) && len(cfg.Certificates) > 0 {
		cert, err := tlsRSAFor(cfg.Certificates[0])
		if err != nil {
			return nil, err
		}
		if hello.sslv2 {
			sc := ssl2.NewConn(rc)
			if _, err := sc.ServerHandshake(&ssl2.Config{Certificate: cert.der, PrivateKey: cert.key}); err != nil {
				return nil, err
			}
			return &tlsUpgradedConn{Conn: conn, rw: sc}, nil
		}
		tc := ltls.Server(rc, &ltls.Config{
			Certificates:           []ltls.Certificate{cert.legacy},
			CipherSuites:           tlsLegacySuiteIDs,
			MinVersion:             ltls.VersionSSL30,
			MaxVersion:             ltls.VersionTLS12,
			ExportRSAKey:           tlsExportRSAKey(),
			SessionTicketsDisabled: true,
		})
		if err := tc.Handshake(); err != nil {
			return nil, err
		}
		return &tlsUpgradedConn{Conn: conn, rw: tc}, nil
	}
	tc := tls.Server(rc, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}

// listenTLS listens on addr and returns connections that terminate TLS (or
// SSL 2.0/3.0) with handshakeTLS on first use, like tls.Listen.
func listenTLS(network, addr string, cfg *tls.Config) (net.Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &tlsListener{Listener: l, cfg: cfg}, nil
}

type tlsListener struct {
	net.Listener
	cfg *tls.Config
}

func (l *tlsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tlsLazyConn{Conn: c, cfg: l.cfg}, nil
}

// tlsLazyConn runs the handshake on the first Read or Write, as tls.Conn does;
// the caller's deadlines on the connection bound it.
type tlsLazyConn struct {
	net.Conn
	cfg   *tls.Config
	once  sync.Once
	inner net.Conn
	err   error
}

func (c *tlsLazyConn) handshake() error {
	c.once.Do(func() { c.inner, c.err = handshakeTLS(c.Conn, c.cfg) })
	return c.err
}

func (c *tlsLazyConn) Read(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Read(p)
}

func (c *tlsLazyConn) Write(p []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.inner.Write(p)
}
