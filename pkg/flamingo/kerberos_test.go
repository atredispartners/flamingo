package flamingo

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The encoders below build AS-REQ messages the way a client would, with their
// own struct definitions, so that a mistake in the listener's decoder cannot
// cancel out against the same mistake in the test input.

type krbTestPrincipal struct {
	NameType   int32           `asn1:"explicit,tag:0"`
	NameString []asn1.RawValue `asn1:"explicit,tag:1"`
}

type krbTestPAData struct {
	Type  int32  `asn1:"explicit,tag:1"`
	Value []byte `asn1:"explicit,tag:2"`
}

type krbTestEncData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// krbTestBody is KDC-REQ-BODY. Realm carries its own context tag because the
// standard library will not encode a GeneralString on its own.
type krbTestBody struct {
	KDCOptions asn1.BitString   `asn1:"explicit,tag:0"`
	CName      krbTestPrincipal `asn1:"explicit,optional,tag:1"`
	Realm      asn1.RawValue
	SName      krbTestPrincipal `asn1:"explicit,optional,tag:3"`
	Till       time.Time        `asn1:"generalized,explicit,tag:5"`
	Nonce      int64            `asn1:"explicit,tag:7"`
	EType      []int32          `asn1:"explicit,tag:8"`
}

type krbTestKDCReq struct {
	PVNO    int             `asn1:"explicit,tag:1"`
	MsgType int             `asn1:"explicit,tag:2"`
	PAData  []krbTestPAData `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue
}

// krbTestString encodes a KerberosString inside an explicit context tag.
func krbTestString(tag int, s string) asn1.RawValue {
	inner, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagGeneralString,
		Bytes: []byte(s),
	})
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func krbTestName(nameType int32, parts ...string) krbTestPrincipal {
	name := krbTestPrincipal{NameType: nameType}
	for _, p := range parts {
		name.NameString = append(name.NameString, asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagGeneralString,
			Bytes: []byte(p),
		})
	}
	return name
}

// krbTestPreAuth builds a PA-ENC-TIMESTAMP entry around a ciphertext.
func krbTestPreAuth(t *testing.T, etype int32, cipher []byte) krbTestPAData {
	t.Helper()
	v, err := asn1.Marshal(krbTestEncData{EType: etype, Cipher: cipher})
	if err != nil {
		t.Fatalf("encoding PA-ENC-TIMESTAMP: %s", err)
	}
	return krbTestPAData{Type: kerberosPATypeEncTimestamp, Value: v}
}

// krbTestKDCRequest builds an AS-REQ (message type 10) or TGS-REQ (12).
func krbTestKDCRequest(t *testing.T, msgType int, cname, realm string, etypes []int32, pas []krbTestPAData) []byte {
	t.Helper()
	body := krbTestBody{
		KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x81, 0x00, 0x10}, BitLength: 32},
		Realm:      krbTestString(2, realm),
		SName:      krbTestName(kerberosNameTypeSrvInst, "krbtgt", realm),
		Till:       time.Now().UTC().Add(time.Hour).Truncate(time.Second),
		Nonce:      1234567,
		EType:      etypes,
	}
	if cname != "" {
		body.CName = krbTestName(kerberosNameTypePrincipal, cname)
	}
	bodyDER, err := asn1.Marshal(body)
	if err != nil {
		t.Fatalf("encoding KDC-REQ-BODY: %s", err)
	}
	req := krbTestKDCReq{
		PVNO:    kerberosPVNO,
		MsgType: msgType,
		PAData:  pas,
		ReqBody: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: bodyDER},
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		t.Fatalf("encoding KDC-REQ: %s", err)
	}
	msg, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        msgType,
		IsCompound: true,
		Bytes:      reqDER,
	})
	if err != nil {
		t.Fatalf("wrapping KDC-REQ: %s", err)
	}
	return msg
}

// The KRB-ERROR decoder used to check replies. Decoding the realm and the
// principal names as plain strings also proves the listener wrapped its
// GeneralStrings in the right context tags.

type krbTestErrPrincipal struct {
	NameType   int32    `asn1:"explicit,optional,tag:0"`
	NameString []string `asn1:"explicit,optional,tag:1"`
}

type krbTestErr struct {
	PVNO      int                 `asn1:"explicit,tag:0"`
	MsgType   int                 `asn1:"explicit,tag:1"`
	CTime     time.Time           `asn1:"generalized,explicit,optional,tag:2"`
	Cusec     int                 `asn1:"explicit,optional,tag:3"`
	STime     time.Time           `asn1:"generalized,explicit,tag:4"`
	Susec     int                 `asn1:"explicit,tag:5"`
	ErrorCode int32               `asn1:"explicit,tag:6"`
	CRealm    string              `asn1:"explicit,optional,tag:7"`
	CName     krbTestErrPrincipal `asn1:"explicit,optional,tag:8"`
	Realm     string              `asn1:"explicit,tag:9"`
	SName     krbTestErrPrincipal `asn1:"explicit,tag:10"`
	EText     string              `asn1:"explicit,optional,tag:11"`
	EData     []byte              `asn1:"explicit,optional,tag:12"`
}

func krbTestParseErr(t *testing.T, b []byte) krbTestErr {
	t.Helper()
	var e krbTestErr
	if _, err := asn1.UnmarshalWithParams(b, &e, "application,explicit,tag:30"); err != nil {
		t.Fatalf("decoding KRB-ERROR: %s (%x)", err, b)
	}
	if e.MsgType != kerberosMsgKRBError {
		t.Fatalf("reply message type = %d, want %d", e.MsgType, kerberosMsgKRBError)
	}
	if e.PVNO != kerberosPVNO {
		t.Fatalf("reply pvno = %d, want %d", e.PVNO, kerberosPVNO)
	}
	return e
}

// METHOD-DATA as carried in the e-data of a KDC_ERR_PREAUTH_REQUIRED error.

type krbTestETypeInfo2Entry struct {
	EType int32  `asn1:"explicit,tag:0"`
	Salt  string `asn1:"explicit,optional,tag:1"`
}

func krbTestMethodData(t *testing.T, b []byte) []krbTestPAData {
	t.Helper()
	var pas []krbTestPAData
	if _, err := asn1.Unmarshal(b, &pas); err != nil {
		t.Fatalf("decoding METHOD-DATA: %s (%x)", err, b)
	}
	return pas
}

// kerberosTestServer spawns a KDC on free TCP and UDP ports and returns the
// configuration plus a channel that receives every record it writes.
func kerberosTestServer(t *testing.T) (*ConfKerberos, chan map[string]string) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 16)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfKerberos()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnKerberos(conf); err != nil {
		t.Fatalf("SpawnKerberos failed: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return conf, got
}

func kerberosTCPAddr(c *ConfKerberos) string { return c.listener.Addr().String() }
func kerberosUDPAddr(c *ConfKerberos) string { return c.packet.LocalAddr().String() }

func kerberosWaitRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no record written")
		return nil
	}
}

// kerberosTCPDial opens a connection with a test deadline on it.
func kerberosTCPDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// kerberosTCPSend writes one length-prefixed message.
func kerberosTCPSend(t *testing.T, conn net.Conn, msg []byte) {
	t.Helper()
	if err := kerberosWriteMessage(conn, msg); err != nil {
		t.Fatalf("write failed: %s", err)
	}
}

// kerberosTCPRecv reads one length-prefixed reply.
func kerberosTCPRecv(t *testing.T, conn net.Conn) ([]byte, error) {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > kerberosMaxMessage {
		t.Fatalf("reply length %d is out of range", n)
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// kerberosTCPExchange sends one message and reads the reply on a fresh connection.
func kerberosTCPExchange(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	conn := kerberosTCPDial(t, addr)
	kerberosTCPSend(t, conn, msg)
	reply, err := kerberosTCPRecv(t, conn)
	if err != nil {
		t.Fatalf("no reply: %s", err)
	}
	return reply
}

// kerberosUDPExchange sends one datagram and reads the reply.
func kerberosUDPExchange(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("udp dial failed: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("udp write failed: %s", err)
	}
	buf := make([]byte, kerberosMaxMessage)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no udp reply: %s", err)
	}
	return buf[:n]
}

// krbTestCipher is a stand-in for an encrypted timestamp: sixteen bytes of
// RC4-HMAC checksum followed by a confounder and ciphertext.
var krbTestCipher = append(
	[]byte{0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9},
	[]byte{
		0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xb0, 0xb1, 0xb2,
		0xcc, 0xcd, 0xce, 0xcf, 0xc0, 0xc1, 0xc2, 0xc3,
		0xdd, 0xde, 0xdf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4,
		0xee, 0xef, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
	}...)

func TestNewConfKerberos(t *testing.T) {
	conf := NewConfKerberos()
	if conf.BindPort != 88 {
		t.Errorf("default port = %d, want 88", conf.BindPort)
	}
	if conf.Realm != "FLAMINGO.LOCAL" {
		t.Errorf("default realm = %q, want FLAMINGO.LOCAL", conf.Realm)
	}
	if conf.ForceNTLM {
		t.Error("ForceNTLM defaults to true")
	}
	if conf.IsShutdown() {
		t.Error("a new configuration reports itself shut down")
	}
}

// TestKerberosPreAuthHashcat covers the three hashcat layouts, and in
// particular the block flip the RC4 line needs: hashcat 7500 wants the
// 16-byte HMAC checksum at the end of the ciphertext, not at the front.
func TestKerberosPreAuthHashcat(t *testing.T) {
	full := hex.EncodeToString(krbTestCipher)
	checksum, rest := full[:32], full[32:]

	cases := []struct {
		name   string
		etype  int32
		cipher []byte
		want   string
		mode   int
	}{
		{
			name:   "rc4 flips the checksum to the end",
			etype:  kerberosEtypeRC4HMAC,
			cipher: krbTestCipher,
			want:   "$krb5pa$23$alice$FLAMINGO.LOCAL$dummy$" + rest + checksum,
			mode:   KerberosHashcatModePreAuthRC4,
		},
		{
			name:   "aes128 is verbatim",
			etype:  kerberosEtypeAES128,
			cipher: krbTestCipher,
			want:   "$krb5pa$17$alice$FLAMINGO.LOCAL$" + full,
			mode:   KerberosHashcatModePreAuthAES128,
		},
		{
			name:   "aes256 is verbatim",
			etype:  kerberosEtypeAES256,
			cipher: krbTestCipher,
			want:   "$krb5pa$18$alice$FLAMINGO.LOCAL$" + full,
			mode:   KerberosHashcatModePreAuthAES256,
		},
		{
			name:   "unsupported etype yields nothing",
			etype:  3,
			cipher: krbTestCipher,
			want:   "",
			mode:   0,
		},
		{
			name:   "rc4 shorter than its checksum yields nothing",
			etype:  kerberosEtypeRC4HMAC,
			cipher: krbTestCipher[:16],
			want:   "",
			mode:   0,
		},
		{
			name:   "empty ciphertext yields nothing",
			etype:  kerberosEtypeRC4HMAC,
			cipher: nil,
			want:   "",
			mode:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, mode := KerberosPreAuthHashcat("alice", "FLAMINGO.LOCAL", tc.etype, tc.cipher)
			if line != tc.want {
				t.Errorf("line = %q, want %q", line, tc.want)
			}
			if mode != tc.mode {
				t.Errorf("mode = %d, want %d", mode, tc.mode)
			}
		})
	}

	// The flip has to be reversible: putting the last 32 hex characters back
	// in front has to reproduce the ciphertext exactly.
	line, _ := KerberosPreAuthHashcat("alice", "FLAMINGO.LOCAL", kerberosEtypeRC4HMAC, krbTestCipher)
	parts := strings.Split(line, "$")
	if len(parts) != 7 {
		t.Fatalf("7500 line has %d fields: %q", len(parts), line)
	}
	blob := parts[6]
	if got := blob[len(blob)-32:] + blob[:len(blob)-32]; got != full {
		t.Errorf("unflipped blob = %q, want %q", got, full)
	}
}

// TestKerberosPreAuthCapture drives a real listener over TCP with an AS-REQ
// that carries PA-ENC-TIMESTAMP, for each encryption type flamingo cracks.
func TestKerberosPreAuthCapture(t *testing.T) {
	full := hex.EncodeToString(krbTestCipher)

	cases := []struct {
		name  string
		etype int32
		want  string
		mode  string
	}{
		{"rc4", kerberosEtypeRC4HMAC, "$krb5pa$23$alice$CORP.LOCAL$dummy$" + full[32:] + full[:32], "7500"},
		{"aes128", kerberosEtypeAES128, "$krb5pa$17$alice$CORP.LOCAL$" + full, "19800"},
		{"aes256", kerberosEtypeAES256, "$krb5pa$18$alice$CORP.LOCAL$" + full, "19900"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf, got := kerberosTestServer(t)
			req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
				[]int32{tc.etype}, []krbTestPAData{krbTestPreAuth(t, tc.etype, krbTestCipher)})

			reply := kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
			rec := kerberosWaitRecord(t, got)

			if rec["_type"] != "credential" || rec["_proto"] != "kerberos" {
				t.Errorf("record is %s/%s, want credential/kerberos", rec["_type"], rec["_proto"])
			}
			if rec["username"] != "alice" {
				t.Errorf("username = %q, want alice", rec["username"])
			}
			if rec["realm"] != "CORP.LOCAL" {
				t.Errorf("realm = %q, want CORP.LOCAL", rec["realm"])
			}
			if rec["hashcat"] != tc.want {
				t.Errorf("hashcat = %q, want %q", rec["hashcat"], tc.want)
			}
			if rec["hashcat_mode"] != tc.mode {
				t.Errorf("hashcat_mode = %q, want %q", rec["hashcat_mode"], tc.mode)
			}
			if rec["transport"] != "tcp" {
				t.Errorf("transport = %q, want tcp", rec["transport"])
			}
			if _, ok := rec["cipher"]; ok {
				t.Error("record carries a raw cipher field alongside a hashcat line")
			}

			// Having taken the credential there is no ticket to hand back,
			// so the exchange ends the way a wrong password would.
			e := krbTestParseErr(t, reply)
			if e.ErrorCode != kerberosErrPreAuthFailed {
				t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthFailed)
			}
			if e.Realm != "CORP.LOCAL" {
				t.Errorf("reply realm = %q, want CORP.LOCAL", e.Realm)
			}
			if strings.Join(e.SName.NameString, "/") != "krbtgt/CORP.LOCAL" {
				t.Errorf("reply sname = %q, want krbtgt/CORP.LOCAL", e.SName.NameString)
			}
		})
	}
}

// TestKerberosPreAuthCaptureUDP runs the same capture over a bare datagram.
func TestKerberosPreAuthCaptureUDP(t *testing.T) {
	conf, got := kerberosTestServer(t)
	full := hex.EncodeToString(krbTestCipher)

	req := krbTestKDCRequest(t, kerberosMsgASReq, "bob", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})

	reply := kerberosUDPExchange(t, kerberosUDPAddr(conf), req)
	rec := kerberosWaitRecord(t, got)

	want := "$krb5pa$23$bob$CORP.LOCAL$dummy$" + full[32:] + full[:32]
	if rec["hashcat"] != want {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "7500" {
		t.Errorf("hashcat_mode = %q, want 7500", rec["hashcat_mode"])
	}
	if rec["transport"] != "udp" {
		t.Errorf("transport = %q, want udp", rec["transport"])
	}
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrPreAuthFailed {
		t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthFailed)
	}
}

// TestKerberosUnsupportedEtypeKeepsCipher checks that an encryption type with
// no hashcat layout still records the ciphertext rather than dropping it.
func TestKerberosUnsupportedEtypeKeepsCipher(t *testing.T) {
	conf, got := kerberosTestServer(t)
	req := krbTestKDCRequest(t, kerberosMsgASReq, "carol", "CORP.LOCAL",
		[]int32{16}, []krbTestPAData{krbTestPreAuth(t, 16, krbTestCipher)})

	kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
	rec := kerberosWaitRecord(t, got)

	if _, ok := rec["hashcat"]; ok {
		t.Errorf("unsupported etype produced a hashcat line: %q", rec["hashcat"])
	}
	if rec["cipher"] != hex.EncodeToString(krbTestCipher) {
		t.Errorf("cipher = %q, want the raw ciphertext", rec["cipher"])
	}
	if rec["etype"] != "16" {
		t.Errorf("etype = %q, want 16", rec["etype"])
	}
}

// TestKerberosPreAuthRequired covers the exchange that makes the capture
// happen: a bare AS-REQ has to come back with KDC_ERR_PREAUTH_REQUIRED and
// the encryption type hints a client needs to build its timestamp.
func TestKerberosPreAuthRequired(t *testing.T) {
	conf, got := kerberosTestServer(t)
	req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
		[]int32{kerberosEtypeAES256, kerberosEtypeRC4HMAC}, nil)

	reply := kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
	rec := kerberosWaitRecord(t, got)

	if rec["_type"] != "query" {
		t.Errorf("record type = %q, want query", rec["_type"])
	}
	if rec["username"] != "alice" || rec["preauth"] != "false" {
		t.Errorf("record = %v, want a bare AS-REQ from alice", rec)
	}
	if rec["answer"] != "KDC_ERR_PREAUTH_REQUIRED" {
		t.Errorf("answer = %q, want KDC_ERR_PREAUTH_REQUIRED", rec["answer"])
	}

	e := krbTestParseErr(t, reply)
	if e.ErrorCode != kerberosErrPreAuthRequired {
		t.Fatalf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthRequired)
	}
	if e.CRealm != "CORP.LOCAL" || strings.Join(e.CName.NameString, "/") != "alice" {
		t.Errorf("client principal = %q@%q, want alice@CORP.LOCAL", e.CName.NameString, e.CRealm)
	}

	pas := krbTestMethodData(t, e.EData)
	if len(pas) != 2 {
		t.Fatalf("e-data holds %d entries, want 2", len(pas))
	}
	if pas[0].Type != kerberosPATypeEncTimestamp || len(pas[0].Value) != 0 {
		t.Errorf("first entry = type %d (%d bytes), want an empty PA-ENC-TIMESTAMP", pas[0].Type, len(pas[0].Value))
	}
	if pas[1].Type != kerberosPATypeETypeInfo2 {
		t.Fatalf("second entry = type %d, want PA-ETYPE-INFO2", pas[1].Type)
	}

	var info []krbTestETypeInfo2Entry
	if _, err := asn1.Unmarshal(pas[1].Value, &info); err != nil {
		t.Fatalf("decoding PA-ETYPE-INFO2: %s", err)
	}
	if len(info) != 2 {
		t.Fatalf("PA-ETYPE-INFO2 holds %d entries, want 2", len(info))
	}
	// RC4 is offered first because it cracks fastest, and it carries no salt.
	if info[0].EType != kerberosEtypeRC4HMAC || info[0].Salt != "" {
		t.Errorf("first entry = etype %d salt %q, want RC4 with no salt", info[0].EType, info[0].Salt)
	}
	if info[1].EType != kerberosEtypeAES256 || info[1].Salt != "CORP.LOCALalice" {
		t.Errorf("second entry = etype %d salt %q, want AES256 salted CORP.LOCALalice",
			info[1].EType, info[1].Salt)
	}
}

// TestKerberosPreAuthRequiredUnsupportedEtypes checks that a client offering
// nothing flamingo can crack is told so rather than asked for a timestamp it
// would build with an unusable key.
func TestKerberosPreAuthRequiredUnsupportedEtypes(t *testing.T) {
	conf, got := kerberosTestServer(t)
	req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL", []int32{1, 3}, nil)

	reply := kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
	rec := kerberosWaitRecord(t, got)

	if rec["answer"] != "KDC_ERR_ETYPE_NOSUPP" {
		t.Errorf("answer = %q, want KDC_ERR_ETYPE_NOSUPP", rec["answer"])
	}
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrEtypeNoSupp {
		t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrEtypeNoSupp)
	}
}

// TestKerberosForceNTLM checks the mode that pushes a Windows client off
// Kerberos entirely: every AS-REQ is answered KDC_ERR_ETYPE_NOSUPP, and
// pre-authentication that does arrive is still recorded first.
func TestKerberosForceNTLM(t *testing.T) {
	t.Run("bare AS-REQ", func(t *testing.T) {
		conf, got := kerberosTestServer(t)
		conf.ForceNTLM = true

		req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
			[]int32{kerberosEtypeRC4HMAC, kerberosEtypeAES256}, nil)
		reply := kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
		rec := kerberosWaitRecord(t, got)

		if rec["answer"] != "KDC_ERR_ETYPE_NOSUPP" {
			t.Errorf("answer = %q, want KDC_ERR_ETYPE_NOSUPP", rec["answer"])
		}
		e := krbTestParseErr(t, reply)
		if e.ErrorCode != kerberosErrEtypeNoSupp {
			t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrEtypeNoSupp)
		}
		if len(e.EData) != 0 {
			t.Error("the etype refusal carries pre-authentication hints")
		}
	})

	t.Run("AS-REQ with pre-auth is still captured", func(t *testing.T) {
		conf, got := kerberosTestServer(t)
		conf.ForceNTLM = true

		req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
			[]int32{kerberosEtypeRC4HMAC},
			[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})
		reply := kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
		rec := kerberosWaitRecord(t, got)

		if rec["_type"] != "credential" || rec["hashcat_mode"] != "7500" {
			t.Errorf("record = %v, want a 7500 credential", rec)
		}
		if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrEtypeNoSupp {
			t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrEtypeNoSupp)
		}
	})
}

// TestKerberosFullExchange walks the two-message conversation a real client
// has, on one connection: a bare AS-REQ, then the retry carrying the
// encrypted timestamp built from the hints in the first reply.
func TestKerberosFullExchange(t *testing.T) {
	conf, got := kerberosTestServer(t)
	conn := kerberosTCPDial(t, kerberosTCPAddr(conf))

	bare := krbTestKDCRequest(t, kerberosMsgASReq, "dave", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC}, nil)
	kerberosTCPSend(t, conn, bare)
	reply, err := kerberosTCPRecv(t, conn)
	if err != nil {
		t.Fatalf("no reply to the bare AS-REQ: %s", err)
	}
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrPreAuthRequired {
		t.Fatalf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthRequired)
	}
	if rec := kerberosWaitRecord(t, got); rec["_type"] != "query" {
		t.Errorf("first record type = %q, want query", rec["_type"])
	}

	retry := krbTestKDCRequest(t, kerberosMsgASReq, "dave", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})
	kerberosTCPSend(t, conn, retry)
	reply, err = kerberosTCPRecv(t, conn)
	if err != nil {
		t.Fatalf("no reply to the retry: %s", err)
	}
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrPreAuthFailed {
		t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthFailed)
	}
	rec := kerberosWaitRecord(t, got)
	if rec["_type"] != "credential" || rec["username"] != "dave" {
		t.Errorf("second record = %v, want a credential for dave", rec)
	}
}

// TestKerberosOtherMessageTypes checks that a message flamingo does not serve
// is still observed rather than dropped in silence.
func TestKerberosOtherMessageTypes(t *testing.T) {
	conf, got := kerberosTestServer(t)

	tgs := krbTestKDCRequest(t, kerberosMsgTGSReq, "alice", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC}, nil)

	conn := kerberosTCPDial(t, kerberosTCPAddr(conf))
	kerberosTCPSend(t, conn, tgs)
	// Nothing is sent back for a TGS-REQ, so the connection closes.
	if _, err := kerberosTCPRecv(t, conn); err == nil {
		t.Error("a TGS-REQ drew a reply")
	}

	rec := kerberosWaitRecord(t, got)
	if rec["_type"] != "query" {
		t.Errorf("record type = %q, want query", rec["_type"])
	}
	if rec["message"] != "tgs-req" || rec["msg_type"] != "12" {
		t.Errorf("record = %v, want a tgs-req observation", rec)
	}
}

// TestKerberosMalformedInput feeds truncated and corrupt messages straight to
// the decoder. None of them may panic, hang or produce a reply.
func TestKerberosMalformedInput(t *testing.T) {
	conf := NewConfKerberos()
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = NewRecordWriter()
	src := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

	good := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})

	cases := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"single zero byte", []byte{0x00}},
		{"application tag alone", []byte{0x6a}},
		{"length without content", []byte{0x6a, 0x82, 0xff, 0xff}},
		{"indefinite length", []byte{0x6a, 0x80, 0x00, 0x00}},
		{"empty sequence", []byte{0x30, 0x00}},
		{"wrong application tag", append([]byte{0x7f}, good[1:]...)},
		{"garbage", []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0x00, 0x01, 0x02}},
		{"nested emptiness", []byte{0x6a, 0x04, 0x30, 0x02, 0x30, 0x00}},
		{"length longer than content", []byte{0x6a, 0x7f, 0x30, 0x02, 0x02, 0x01}},
		{"body replaced with garbage", append(good[:len(good)-8], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)},
	}

	// Every prefix of a valid message is a truncation worth trying.
	for i := 1; i < len(good); i++ {
		cases = append(cases, struct {
			name string
			data []byte
		}{"truncated to " + strconv.Itoa(i), good[:i]})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan []byte, 1)
			go func() { done <- kerberosSafeProcess(conf, src, tc.data) }()
			select {
			case resp := <-done:
				if len(resp) != 0 {
					// A truncation is allowed to decode into something
					// valid, but it must never be a surprise: only a
					// KRB-ERROR may come back.
					krbTestParseErr(t, resp)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the decoder hung")
			}
		})
	}
}

// TestKerberosMalformedOverTheWire sends the same kind of rubbish through the
// listener itself and checks it keeps serving afterwards.
func TestKerberosMalformedOverTheWire(t *testing.T) {
	conf, got := kerberosTestServer(t)
	addr := kerberosTCPAddr(conf)

	for _, data := range [][]byte{
		{0x00},
		{0x6a, 0x82, 0xff, 0xff},
		{0xff, 0xfe, 0xfd, 0xfc},
	} {
		conn := kerberosTCPDial(t, addr)
		kerberosTCPSend(t, conn, data)
		kerberosTCPRecv(t, conn) // a reply is not expected, an error is fine
		conn.Close()
	}

	// Length prefixes the listener has to refuse without reading the body.
	for _, prefix := range []uint32{0x80000001, 0x00ffffff, 0x00000000} {
		conn := kerberosTCPDial(t, addr)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], prefix)
		if _, err := conn.Write(hdr[:]); err != nil {
			t.Fatalf("write failed: %s", err)
		}
		if _, err := kerberosTCPRecv(t, conn); err == nil {
			t.Errorf("length prefix %#08x drew a reply", prefix)
		}
		conn.Close()
	}

	// A bare datagram of nonsense must not take the UDP reader down either.
	udp, err := net.Dial("udp", kerberosUDPAddr(conf))
	if err != nil {
		t.Fatalf("udp dial failed: %s", err)
	}
	udp.Write([]byte{0x6a, 0x01, 0xff})
	udp.Close()

	// The listener is still there.
	req := krbTestKDCRequest(t, kerberosMsgASReq, "alice", "CORP.LOCAL",
		[]int32{kerberosEtypeRC4HMAC},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})
	reply := kerberosTCPExchange(t, addr, req)
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrPreAuthFailed {
		t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthFailed)
	}

	var rec map[string]string
	for {
		rec = kerberosWaitRecord(t, got)
		if rec["_type"] == "credential" {
			break
		}
	}
	if rec["username"] != "alice" {
		t.Errorf("username = %q, want alice", rec["username"])
	}
}

// TestKerberosSplitFrame checks that a message arriving in pieces is
// reassembled from its length prefix rather than parsed per read.
func TestKerberosSplitFrame(t *testing.T) {
	conf, got := kerberosTestServer(t)
	req := krbTestKDCRequest(t, kerberosMsgASReq, "erin", "CORP.LOCAL",
		[]int32{kerberosEtypeAES256},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeAES256, krbTestCipher)})

	conn := kerberosTCPDial(t, kerberosTCPAddr(conf))
	framed := binary.BigEndian.AppendUint32(nil, uint32(len(req)))
	framed = append(framed, req...)

	for i := 0; i < len(framed); i += 7 {
		end := min(i+7, len(framed))
		if _, err := conn.Write(framed[i:end]); err != nil {
			t.Fatalf("write failed: %s", err)
		}
		time.Sleep(time.Millisecond)
	}

	reply, err := kerberosTCPRecv(t, conn)
	if err != nil {
		t.Fatalf("no reply: %s", err)
	}
	if e := krbTestParseErr(t, reply); e.ErrorCode != kerberosErrPreAuthFailed {
		t.Errorf("error code = %d, want %d", e.ErrorCode, kerberosErrPreAuthFailed)
	}
	if rec := kerberosWaitRecord(t, got); rec["hashcat_mode"] != "19900" {
		t.Errorf("hashcat_mode = %q, want 19900", rec["hashcat_mode"])
	}
}

// TestKerberosRealmFallback checks that an AS-REQ with no realm of its own is
// recorded under the realm this KDC claims to serve.
func TestKerberosRealmFallback(t *testing.T) {
	conf, got := kerberosTestServer(t)
	conf.Realm = "FAKE.REALM"

	req := krbTestKDCRequest(t, kerberosMsgASReq, "frank", "",
		[]int32{kerberosEtypeRC4HMAC},
		[]krbTestPAData{krbTestPreAuth(t, kerberosEtypeRC4HMAC, krbTestCipher)})

	kerberosTCPExchange(t, kerberosTCPAddr(conf), req)
	rec := kerberosWaitRecord(t, got)

	if rec["realm"] != "FAKE.REALM" {
		t.Errorf("realm = %q, want FAKE.REALM", rec["realm"])
	}
	if !strings.Contains(rec["hashcat"], "$frank$FAKE.REALM$") {
		t.Errorf("hashcat = %q, want it to name frank@FAKE.REALM", rec["hashcat"])
	}
}

// TestKerberosShutdown checks both sockets close and the service reports it.
func TestKerberosShutdown(t *testing.T) {
	rw := NewRecordWriter()
	conf := NewConfKerberos()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnKerberos(conf); err != nil {
		t.Fatalf("SpawnKerberos failed: %s", err)
	}
	tcpAddr := kerberosTCPAddr(conf)

	if conf.IsShutdown() {
		t.Error("a running service reports itself shut down")
	}
	conf.Shutdown()
	if !conf.IsShutdown() {
		t.Error("a stopped service does not report itself shut down")
	}
	// A second call must not panic on the already closed sockets.
	conf.Shutdown()

	if conn, err := net.DialTimeout("tcp", tcpAddr, time.Second); err == nil {
		conn.Close()
		t.Error("the TCP listener still accepts connections after shutdown")
	}
}
