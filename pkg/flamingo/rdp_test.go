package flamingo

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/md4"
)

// rdpTestCert generates a throwaway self-signed ECDSA cert/key PEM pair.
func rdpTestCert(t *testing.T) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %s", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert create: %s", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("key marshal: %s", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// rdpTestServer spawns an RDP collector on a free port, with a certificate
// when withTLS is set, and returns the address plus a channel that receives
// captured credential records.
func rdpTestServer(t *testing.T, withTLS bool) (string, chan map[string]string, *ConfRDP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfRDP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	if withTLS {
		conf.TLSCert, conf.TLSKey = rdpTestCert(t)
	}

	if err := SpawnRDP(conf); err != nil {
		t.Fatalf("SpawnRDP failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func rdpDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func rdpWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// rdpTestConnReq builds an X.224 Connection Request with an optional cookie
// and RDP_NEG_REQ.
func rdpTestConnReq(cookie string, protocols uint32, neg bool) []byte {
	body := []byte{0, rdpX224CR, 0, 0, 0, 0, 0}
	if cookie != "" {
		body = append(body, "Cookie: mstshash="+cookie+"\r\n"...)
	}
	if neg {
		body = append(body, rdpNegReq, 0, 8, 0)
		body = binary.LittleEndian.AppendUint32(body, protocols)
	}
	body[0] = byte(len(body) - 1)
	return rdpTPKT(body)
}

// rdpTestReadTPKT reads one TPKT from r and returns its payload.
func rdpTestReadTPKT(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("TPKT header: %v", err)
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n < 4 {
		t.Fatalf("TPKT length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("TPKT body: %v", err)
	}
	return body
}

// rdpTestNegotiate sends the Connection Request and checks the Connection
// Confirm selects want.
func rdpTestNegotiate(t *testing.T, c net.Conn, cookie string, protocols, want uint32) {
	t.Helper()
	if _, err := c.Write(rdpTestConnReq(cookie, protocols, true)); err != nil {
		t.Fatal(err)
	}
	cc := rdpTestReadTPKT(t, c)
	if len(cc) != 15 || cc[1] != rdpX224CC || cc[7] != rdpNegRsp || binary.LittleEndian.Uint32(cc[11:15]) != want {
		t.Fatalf("connection confirm: %x", cc)
	}
}

func rdpTestTLSClient(t *testing.T, c net.Conn) *tls.Conn {
	t.Helper()
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("tls: %v", err)
	}
	return tc
}

// rdpTestNegotiateMsg builds an NTLM NEGOTIATE message with a VERSION field.
func rdpTestNegotiateMsg() []byte {
	m := make([]byte, 40)
	copy(m, rdpNTLMSig)
	binary.LittleEndian.PutUint32(m[8:], 1)
	binary.LittleEndian.PutUint32(m[12:], rdpNTLMUnicode|rdpNTLMRequestTarget|rdpNTLMSign|rdpNTLMSeal|
		rdpNTLMNTLM|rdpNTLMAlwaysSign|rdpNTLMExtendedSec|rdpNTLMVersion|rdpNTLM128|rdpNTLMKeyExch|rdpNTLM56)
	copy(m[32:40], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})
	return m
}

// rdpTestAuthenticateMsg builds an NTLM AUTHENTICATE message with Unicode
// strings.
func rdpTestAuthenticateMsg(user, domain, ws string, lm, nt []byte) []byte {
	m := make([]byte, 88)
	copy(m, rdpNTLMSig)
	binary.LittleEndian.PutUint32(m[8:], 3)
	var payload []byte
	put := func(at int, b []byte) {
		binary.LittleEndian.PutUint16(m[at:], uint16(len(b)))
		binary.LittleEndian.PutUint16(m[at+2:], uint16(len(b)))
		binary.LittleEndian.PutUint32(m[at+4:], uint32(len(m)+len(payload)))
		payload = append(payload, b...)
	}
	put(12, lm)
	put(20, nt)
	put(28, rdpUTF16Bytes(domain))
	put(36, rdpUTF16Bytes(user))
	put(44, rdpUTF16Bytes(ws))
	put(52, nil)
	binary.LittleEndian.PutUint32(m[60:], rdpNTLMUnicode|rdpNTLMRequestTarget|rdpNTLMSign|rdpNTLMSeal|
		rdpNTLMNTLM|rdpNTLMAlwaysSign|rdpNTLMExtendedSec|rdpNTLMTargetInfo|rdpNTLMVersion|rdpNTLM128|
		rdpNTLMKeyExch|rdpNTLM56)
	copy(m[64:72], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})
	return append(m, payload...)
}

// rdpTestNTOWFv2 is NTOWFv2(password, user, domain).
func rdpTestNTOWFv2(password, user, domain string) []byte {
	h := md4.New()
	h.Write(rdpUTF16Bytes(password))
	m := hmac.New(md5.New, h.Sum(nil))
	m.Write(rdpUTF16Bytes(strings.ToUpper(user) + domain))
	return m.Sum(nil)
}

// rdpTestNTLMv2Proof computes NTProofStr for an NTLMv2 client blob.
func rdpTestNTLMv2Proof(password, user, domain string, challenge, blob []byte) []byte {
	m := hmac.New(md5.New, rdpTestNTOWFv2(password, user, domain))
	m.Write(challenge)
	m.Write(blob)
	return m.Sum(nil)
}

// rdpTestNTLMv2Blob builds the NTLMv2_CLIENT_CHALLENGE structure around the
// target info of a CHALLENGE message.
func rdpTestNTLMv2Blob(targetInfo []byte) []byte {
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = binary.LittleEndian.AppendUint64(blob, rdpFiletime(time.Now()))
	blob = append(blob, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	return append(blob, 0, 0, 0, 0)
}

// rdpTestConnectInitial builds an MCS Connect Initial with CS_CORE,
// CS_SECURITY and CS_NET blocks.
func rdpTestConnectInitial(name string, channels []string, protocols uint32) []byte {
	core := make([]byte, 216)
	binary.LittleEndian.PutUint32(core[0:], 0x00080004)
	binary.LittleEndian.PutUint16(core[4:], 1024)
	binary.LittleEndian.PutUint16(core[6:], 768)
	binary.LittleEndian.PutUint16(core[8:], 0xca01)
	binary.LittleEndian.PutUint16(core[10:], 0xaa03)
	binary.LittleEndian.PutUint32(core[12:], 0x409)
	binary.LittleEndian.PutUint32(core[16:], 19041)
	copy(core[20:52], rdpUTF16Bytes(name))
	binary.LittleEndian.PutUint32(core[52:], 4)
	binary.LittleEndian.PutUint16(core[128:], 0xca01)
	binary.LittleEndian.PutUint16(core[130:], 1)
	binary.LittleEndian.PutUint16(core[136:], 24)
	binary.LittleEndian.PutUint16(core[138:], 7)
	binary.LittleEndian.PutUint16(core[140:], 1)
	core[206] = 6
	binary.LittleEndian.PutUint32(core[208:], protocols)
	blocks := rdpGCCBlock(rdpCSCore, core)
	blocks = append(blocks, rdpGCCBlock(rdpCSSecurity, make([]byte, 8))...)
	net := binary.LittleEndian.AppendUint32(nil, uint32(len(channels)))
	for _, ch := range channels {
		n := make([]byte, 8)
		copy(n, ch)
		net = append(net, n...)
		net = binary.LittleEndian.AppendUint32(net, 0x80000000)
	}
	blocks = append(blocks, rdpGCCBlock(rdpCSNet, net)...)
	inner := []byte{0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00}
	inner = append(inner, rdpH221ClientKey...)
	inner = append(inner, rdpPERLenBytes(len(blocks))...)
	inner = append(inner, blocks...)
	gcc := append(append([]byte(nil), rdpT124Identifier...), rdpPERLenBytes(len(inner))...)
	gcc = append(gcc, inner...)
	params := rdpDERWrap(0x30, []byte{0x02, 0x01, 0x22, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
		0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xff, 0xff, 0x02, 0x01, 0x02})
	content := []byte{0x04, 0x01, 0x01, 0x04, 0x01, 0x01, 0x01, 0x01, 0xff}
	for i := 0; i < 3; i++ {
		content = append(content, params...)
	}
	content = append(content, rdpDERWrap(0x04, gcc)...)
	out := append([]byte{0x7f, 0x65}, rdpBERLenBytes(len(content))...)
	return append(out, content...)
}

// rdpTestClientInfo builds a TS_INFO_PACKET with Unicode fields and
// extended info.
func rdpTestClientInfo(domain, user, password string) []byte {
	p := binary.LittleEndian.AppendUint32(nil, 0)
	p = binary.LittleEndian.AppendUint32(p, rdpInfoUnicode|0x01|0x08|0x40)
	fields := [][]byte{rdpUTF16Bytes(domain), rdpUTF16Bytes(user), rdpUTF16Bytes(password), nil, nil}
	for _, f := range fields {
		p = binary.LittleEndian.AppendUint16(p, uint16(len(f)))
	}
	for _, f := range fields {
		p = append(p, f...)
		p = append(p, 0, 0)
	}
	p = binary.LittleEndian.AppendUint16(p, 2)
	addr := append(rdpUTF16Bytes("10.1.2.3"), 0, 0)
	p = binary.LittleEndian.AppendUint16(p, uint16(len(addr)))
	p = append(p, addr...)
	dir := append(rdpUTF16Bytes(`C:\Windows\System32\mstscax.dll`), 0, 0)
	p = binary.LittleEndian.AppendUint16(p, uint16(len(dir)))
	return append(p, dir...)
}

// rdpTestSendData frames user data in an MCS Send Data Request to channel ch.
func rdpTestSendData(initiator, ch uint16, data []byte) []byte {
	b := []byte{rdpMCSSendDataRequest << 2}
	b = binary.BigEndian.AppendUint16(b, initiator)
	b = binary.BigEndian.AppendUint16(b, ch)
	b = append(b, 0x70)
	b = append(b, rdpPERLenBytes(len(data))...)
	return rdpX224Data(append(b, data...))
}

// TestRDPCredSSP drives the collector as an NLA client, answers the fixed
// challenge with a genuine NTLMv2 response and verifies the hashcat line
// recovers the known password.
func TestRDPCredSSP(t *testing.T) {
	const user, domain, ws, secret = "Administrator", "CORP", "ATTACKER", "Winter2026!"

	addr, got, conf := rdpTestServer(t, true)
	defer conf.Shutdown()

	c := rdpDial(t, addr)
	rdpTestNegotiate(t, c, "admin", rdpProtocolSSL|rdpProtocolHybrid, rdpProtocolHybrid)
	tc := rdpTestTLSClient(t, c)

	if _, err := tc.Write(rdpEncodeTSRequest(6, rdpTestNegotiateMsg(), nil)); err != nil {
		t.Fatal(err)
	}
	raw, err := rdpReadDER(tc)
	if err != nil {
		t.Fatalf("read challenge: %s", err)
	}
	resp, err := rdpParseTSRequest(raw)
	if err != nil || len(resp.tokens) != 1 || rdpNTLMType(resp.tokens[0]) != 2 {
		t.Fatalf("challenge: %v %+v", err, resp)
	}
	chal := resp.tokens[0]
	challenge := chal[24:32]
	if !bytes.Equal(challenge, RDPNTLMChallenge[:]) {
		t.Fatalf("server challenge %x != fixed %x", challenge, RDPNTLMChallenge[:])
	}
	if target := rdpUTF16String(rdpNTLMSecBuf(chal, 12)); target != rdpDomain {
		t.Fatalf("target name %q, want %q", target, rdpDomain)
	}
	targetInfo := rdpNTLMSecBuf(chal, 40)
	if len(targetInfo) == 0 {
		t.Fatal("challenge has no target info")
	}

	blob := rdpTestNTLMv2Blob(targetInfo)
	proof := rdpTestNTLMv2Proof(secret, user, domain, challenge, blob)
	nt := append(append([]byte(nil), proof...), blob...)
	auth := rdpTestAuthenticateMsg(user, domain, ws, make([]byte, 24), nt)
	if _, err := tc.Write(rdpEncodeTSRequest(6, auth, nil)); err != nil {
		t.Fatal(err)
	}
	raw, err = rdpReadDER(tc)
	if err != nil {
		t.Fatalf("read final TSRequest: %s", err)
	}
	final, err := rdpParseTSRequest(raw)
	if err != nil || !final.hasError || final.errorCode != rdpStatusLogonFailure {
		t.Fatalf("final TSRequest: %v %+v", err, final)
	}

	rec := rdpWaitCred(t, got)
	want := map[string]string{
		"_type":          "credential",
		"_proto":         "rdp",
		"method":         "credssp",
		"username":       user,
		"domain":         domain,
		"workstation":    ws,
		"ntlm_version":   "v2",
		"client_version": "10.0.19043",
		"cookie_user":    "admin",
		"challenge":      hex.EncodeToString(RDPNTLMChallenge[:]),
		"response":       hex.EncodeToString(nt),
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %q, want %q", k, rec[k], v)
		}
	}

	wantHash := user + "::" + domain + ":" + hex.EncodeToString(challenge) + ":" +
		hex.EncodeToString(proof) + ":" + hex.EncodeToString(blob)
	if rec["hashcat"] != wantHash {
		t.Fatalf("hashcat = %q, want %q", rec["hashcat"], wantHash)
	}

	// The captured line must crack back to the known password from its own
	// parts alone, as hashcat mode 5600 would.
	parts := strings.Split(rec["hashcat"], ":")
	if len(parts) != 6 {
		t.Fatalf("hashcat line has %d fields: %q", len(parts), rec["hashcat"])
	}
	gotChal, _ := hex.DecodeString(parts[3])
	gotProof, _ := hex.DecodeString(parts[4])
	gotBlob, _ := hex.DecodeString(parts[5])
	if !bytes.Equal(rdpTestNTLMv2Proof(secret, parts[0], parts[2], gotChal, gotBlob), gotProof) {
		t.Error("captured hashcat line does not recover the known password")
	}
}

// TestRDPClientInfo negotiates TLS-only security, walks the MCS connect
// sequence and verifies the cleartext Client Info credential is captured.
func TestRDPClientInfo(t *testing.T) {
	addr, got, conf := rdpTestServer(t, true)
	defer conf.Shutdown()

	c := rdpDial(t, addr)
	rdpTestNegotiate(t, c, "", rdpProtocolSSL, rdpProtocolSSL)
	tc := rdpTestTLSClient(t, c)

	if _, err := tc.Write(rdpX224Data(rdpTestConnectInitial("DESKTOP-TEST", []string{"cliprdr"}, rdpProtocolSSL))); err != nil {
		t.Fatal(err)
	}
	resp := rdpTestReadTPKT(t, tc)
	if len(resp) < 5 || resp[1] != rdpX224DT || resp[3] != 0x7f || resp[4] != 0x66 {
		t.Fatalf("connect response: %x", resp)
	}
	i := bytes.Index(resp, rdpH221ServerKey)
	if i < 0 {
		t.Fatalf("no conference create response: %x", resp)
	}
	n, hdr, ok := rdpPERLen(resp[i+4:])
	if !ok {
		t.Fatal("bad server data length")
	}
	blocks := resp[i+4+hdr:]
	var chanID uint16
	for len(blocks) >= 4 && n > 0 {
		typ, bl := binary.LittleEndian.Uint16(blocks), int(binary.LittleEndian.Uint16(blocks[2:]))
		if bl < 4 || bl > len(blocks) {
			t.Fatalf("bad server block: %x", blocks)
		}
		if typ == rdpSCNet {
			if binary.LittleEndian.Uint16(blocks[6:]) != 1 {
				t.Fatalf("SC_NET: %x", blocks[:bl])
			}
			chanID = binary.LittleEndian.Uint16(blocks[8:])
		}
		blocks = blocks[bl:]
	}
	if chanID == 0 {
		t.Fatal("no channel id assigned")
	}

	tc.Write(rdpX224Data([]byte{rdpMCSErectDomainRequest << 2, 0x01, 0x00, 0x01, 0x00}))
	tc.Write(rdpX224Data([]byte{rdpMCSAttachUserRequest << 2}))
	auc := rdpTestReadTPKT(t, tc)[3:]
	if len(auc) != 4 || auc[0]>>2 != rdpMCSAttachUserConfirm || auc[1] != 0 {
		t.Fatalf("attach user confirm: %x", auc)
	}
	initiator := binary.BigEndian.Uint16(auc[2:])
	for _, ch := range []uint16{initiator + rdpMCSBaseID, rdpMCSIOChannel, chanID} {
		req := []byte{rdpMCSChannelJoinRequest << 2}
		req = binary.BigEndian.AppendUint16(req, initiator)
		tc.Write(rdpX224Data(binary.BigEndian.AppendUint16(req, ch)))
		cjc := rdpTestReadTPKT(t, tc)[3:]
		if len(cjc) != 8 || cjc[0]>>2 != rdpMCSChannelJoinConfirm || binary.BigEndian.Uint16(cjc[6:]) != ch {
			t.Fatalf("channel join confirm: %x", cjc)
		}
	}

	info := binary.LittleEndian.AppendUint16(nil, rdpSecInfoPkt)
	info = binary.LittleEndian.AppendUint16(info, 0)
	info = append(info, rdpTestClientInfo("CORP", "admin", "Passw0rd!")...)
	if _, err := tc.Write(rdpTestSendData(initiator, rdpMCSIOChannel, info)); err != nil {
		t.Fatal(err)
	}
	dpu := rdpTestReadTPKT(t, tc)[3:]
	if !bytes.Equal(dpu, []byte{rdpMCSDisconnectUltimatum << 2, 0x80}) {
		t.Fatalf("disconnect ultimatum: %x", dpu)
	}

	rec := rdpWaitCred(t, got)
	want := map[string]string{
		"_type":       "credential",
		"_proto":      "rdp",
		"method":      "client_info",
		"username":    "admin",
		"domain":      "CORP",
		"password":    "Passw0rd!",
		"workstation": "DESKTOP-TEST",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %q, want %q", k, rec[k], v)
		}
	}
	if _, ok := rec["cookie_user"]; ok {
		t.Errorf("cookie_user = %q present without a routing cookie", rec["cookie_user"])
	}
}

// TestRDPStandardSecurity verifies a client that only offers standard RDP
// security is confirmed, read through its Connect Initial and closed
// without producing a record.
func TestRDPStandardSecurity(t *testing.T) {
	addr, got, conf := rdpTestServer(t, false)
	defer conf.Shutdown()

	c := rdpDial(t, addr)
	if _, err := c.Write(rdpTestConnReq("legacy", 0, false)); err != nil {
		t.Fatal(err)
	}
	cc := rdpTestReadTPKT(t, c)
	if len(cc) != 7 || cc[1] != rdpX224CC {
		t.Fatalf("legacy connection confirm: %x", cc)
	}
	if _, err := c.Write(rdpX224Data(rdpTestConnectInitial("OLDBOX", nil, 0))); err != nil {
		t.Fatal(err)
	}

	// The server reads the Connect Initial and closes without a reply.
	buf := make([]byte, 64)
	if n, err := c.Read(buf); err != io.EOF {
		t.Fatalf("expected clean close, got %d bytes, err %v", n, err)
	}
	select {
	case rec := <-got:
		t.Fatalf("unexpected record for standard security: %v", rec)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestRDPNoCertDowngrade verifies that without a certificate a client
// requesting NLA is confirmed with standard security rather than failed.
func TestRDPNoCertDowngrade(t *testing.T) {
	addr, _, conf := rdpTestServer(t, false)
	defer conf.Shutdown()

	c := rdpDial(t, addr)
	rdpTestNegotiate(t, c, "", rdpProtocolSSL|rdpProtocolHybrid, rdpProtocolRDP)
}
