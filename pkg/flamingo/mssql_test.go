package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// mssqlTestServer spawns an MSSQL collector on a free port and returns the
// address plus a channel that receives captured credential records.
func mssqlTestServer(t *testing.T) (string, chan map[string]string, *ConfMSSQL) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfMSSQL()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnMSSQL(conf); err != nil {
		t.Fatalf("SpawnMSSQL failed: %s", err)
	}
	return conf.listener.Addr().String(), got, conf
}

func mssqlDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func mssqlWaitCred(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no credential captured")
		return nil
	}
}

// mssqlPacket wraps a payload in a TDS packet header.
func mssqlPacket(typ byte, status byte, payload []byte) []byte {
	pkt := []byte{typ, status, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(pkt[2:], uint16(8+len(payload)))
	return append(pkt, payload...)
}

// mssqlTestPrelogin builds a client PRELOGIN payload asking for ENCRYPT_OFF.
func mssqlTestPrelogin() []byte {
	opts := []struct {
		tok  byte
		data []byte
	}{
		{mssqlPreVersion, []byte{9, 0, 0, 0, 0, 0}},
		{mssqlPreEncryption, []byte{0x00}},
		{mssqlPreInstance, []byte{0}},
		{mssqlPreThreadID, []byte{0, 0, 0, 1}},
		{mssqlPreMARS, []byte{0}},
	}
	off := len(opts)*5 + 1
	var hdr, data []byte
	for _, op := range opts {
		hdr = append(hdr, op.tok)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(off+len(data)))
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(op.data)))
		data = append(data, op.data...)
	}
	hdr = append(hdr, mssqlPreTerminator)
	return append(hdr, data...)
}

// mssqlLogin7Fields are the variable strings placed in a test LOGIN7 message.
type mssqlLogin7Fields struct {
	host, user, pw, app, server, lib, lang, db, newPw string
	sspi                                              []byte
}

// mssqlTestLogin7 builds a LOGIN7 payload for the given TDS version with
// UTF-16LE strings and an obfuscated password.
func mssqlTestLogin7(version uint32, f mssqlLogin7Fields) []byte {
	hdrLen := mssqlLoginHdrLen71
	if version>>24 >= 0x72 {
		hdrLen = mssqlLoginHdrLen72
	}
	hdr := make([]byte, hdrLen)
	le := binary.LittleEndian
	le.PutUint32(hdr[4:], version)
	le.PutUint32(hdr[8:], 4096)
	le.PutUint32(hdr[12:], 0x07000000)
	le.PutUint32(hdr[16:], 3600)
	le.PutUint32(hdr[32:], 0x409)
	copy(hdr[72:], []byte{0x08, 0x00, 0x27, 0xff, 0xff, 0xff})
	var data []byte
	put := func(at int, s string, password bool) {
		u := utf16.Encode([]rune(s))
		b := make([]byte, 2*len(u))
		for i, v := range u {
			le.PutUint16(b[2*i:], v)
		}
		if password {
			for i, v := range b {
				v = v<<4 | v>>4
				b[i] = v ^ 0xa5
			}
		}
		le.PutUint16(hdr[at:], uint16(hdrLen+len(data)))
		le.PutUint16(hdr[at+2:], uint16(len(u)))
		data = append(data, b...)
	}
	put(36, f.host, false)
	put(40, f.user, false)
	put(44, f.pw, true)
	put(48, f.app, false)
	put(52, f.server, false)
	put(60, f.lib, false)
	put(64, f.lang, false)
	put(68, f.db, false)
	// ibSSPI and cbSSPI follow the 6-byte ClientID at offset 72.
	le.PutUint16(hdr[78:], uint16(hdrLen+len(data)))
	le.PutUint16(hdr[80:], uint16(len(f.sspi)))
	if len(f.sspi) > 0 {
		hdr[25] |= 0x80
	}
	data = append(data, f.sspi...)
	le.PutUint16(hdr[82:], uint16(hdrLen+len(data)))
	if hdrLen == mssqlLoginHdrLen72 {
		put(86, f.newPw, true)
	}
	msg := append(hdr, data...)
	le.PutUint32(msg[0:], uint32(len(msg)))
	return msg
}

// mssqlReadResponse reads one TDS response message from the server.
func mssqlReadResponse(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	typ, msg, err := mssqlReadMessage(conn)
	if err != nil {
		t.Fatalf("read response: %s", err)
	}
	return typ, msg
}

// mssqlPreloginEncryption returns the encryption byte from a PRELOGIN response.
func mssqlPreloginEncryption(t *testing.T, p []byte) byte {
	t.Helper()
	for off := 0; off+5 <= len(p) && p[off] != mssqlPreTerminator; off += 5 {
		start := int(binary.BigEndian.Uint16(p[off+1:]))
		size := int(binary.BigEndian.Uint16(p[off+3:]))
		if p[off] == mssqlPreEncryption && size >= 1 && start+size <= len(p) {
			return p[start]
		}
	}
	t.Fatal("no encryption option in PRELOGIN response")
	return 0
}

// mssqlCheckError verifies a tabular response carries an ERROR token with the
// given number and message text followed by a DONE token.
func mssqlCheckError(t *testing.T, typ byte, msg []byte, number uint32, text string) {
	t.Helper()
	if typ != mssqlPktTabular {
		t.Fatalf("response type 0x%02x, want tabular", typ)
	}
	if len(msg) < 3 || msg[0] != 0xaa {
		t.Fatalf("response does not start with an ERROR token: % x", msg)
	}
	le := binary.LittleEndian
	n := int(le.Uint16(msg[1:]))
	tok := msg[3 : 3+n]
	if got := le.Uint32(tok); got != number {
		t.Errorf("error number %d, want %d", got, number)
	}
	cch := int(le.Uint16(tok[6:]))
	u := make([]uint16, cch)
	for i := range u {
		u[i] = le.Uint16(tok[8+2*i:])
	}
	if got := string(utf16.Decode(u)); !strings.Contains(got, text) {
		t.Errorf("error message %q does not contain %q", got, text)
	}
	if rest := msg[3+n:]; len(rest) < 13 || rest[0] != 0xfd {
		t.Errorf("missing DONE token after ERROR: % x", rest)
	}
}

// mssqlHandshake sends PRELOGIN and checks the server declines encryption.
func mssqlHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write(mssqlPacket(mssqlPktPrelogin, 0x01, mssqlTestPrelogin())); err != nil {
		t.Fatalf("write prelogin: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	if typ != mssqlPktTabular {
		t.Fatalf("prelogin response type 0x%02x, want tabular", typ)
	}
	if enc := mssqlPreloginEncryption(t, msg); enc != mssqlEncryptNotSup {
		t.Fatalf("prelogin encryption 0x%02x, want ENCRYPT_NOT_SUP", enc)
	}
}

func TestMSSQLLogin7(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	login := mssqlTestLogin7(0x74000004, mssqlLogin7Fields{
		host:   "WIN-CLIENT",
		user:   "sa",
		pw:     "Tr0ub4dor&3",
		app:    "sqlcmd",
		server: "db.example.test",
		lib:    "ODBC",
		lang:   "us_english",
		db:     "master",
		newPw:  "NewPass1",
	})
	if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, login)); err != nil {
		t.Fatalf("write login7: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	mssqlCheckError(t, typ, msg, 18456, "Login failed for user 'sa'.")

	rec := mssqlWaitCred(t, got)
	want := map[string]string{
		"_type":           "credential",
		"_proto":          "mssql",
		"_server":         "127.0.0.1:0",
		"username":        "sa",
		"password":        "Tr0ub4dor&3",
		"database":        "master",
		"hostname":        "WIN-CLIENT",
		"app_name":        "sqlcmd",
		"server_name":     "db.example.test",
		"library":         "ODBC",
		"language":        "us_english",
		"change_password": "NewPass1",
		"method":          "sql",
		"tds_version":     "0x74000004",
		"client_pid":      "3600",
		"client_version":  "0x07000000",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}

	// The server closes after the login failure.
	if _, err := io.ReadAll(conn); err != nil {
		t.Errorf("read after close: %s", err)
	}
}

func TestMSSQLLogin7Split(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	// TDS 7.1 header without the change password fields, as sent by older
	// OLEDB clients, delivered in two packets.
	login := mssqlTestLogin7(0x71000001, mssqlLogin7Fields{
		host:   "scanner01",
		user:   "admin",
		pw:     "password123",
		app:    "OLEDB",
		server: "10.0.0.5",
		lib:    "OLEDB",
		db:     "appdb",
	})
	cut := len(login) / 2
	var buf bytes.Buffer
	buf.Write(mssqlPacket(mssqlPktLogin7, 0x00, login[:cut]))
	buf.Write(mssqlPacket(mssqlPktLogin7, 0x01, login[cut:]))
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("write login7: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	mssqlCheckError(t, typ, msg, 18456, "Login failed for user 'admin'.")

	rec := mssqlWaitCred(t, got)
	if rec["username"] != "admin" || rec["password"] != "password123" {
		t.Errorf("captured %q/%q, want admin/password123", rec["username"], rec["password"])
	}
	if rec["database"] != "appdb" || rec["hostname"] != "scanner01" || rec["library"] != "OLEDB" {
		t.Errorf("unexpected fields: %v", rec)
	}
	if rec["tds_version"] != "0x71000001" || rec["method"] != "sql" {
		t.Errorf("tds_version %q method %q", rec["tds_version"], rec["method"])
	}
	if _, ok := rec["change_password"]; ok {
		t.Errorf("TDS 7.1 login should not carry a change password")
	}
}

// mssqlNTLMLogin is a Windows Authentication LOGIN7: no user name or password,
// an NTLMSSP NEGOTIATE in the SSPI field.
func mssqlNTLMLogin(token []byte) []byte {
	return mssqlTestLogin7(0x74000004, mssqlLogin7Fields{
		host:   "CORP-PC",
		app:    "SSMS",
		server: "sql01.corp.test",
		lib:    "ODBC",
		db:     "master",
		sspi:   token,
	})
}

// TestMSSQLNTLM drives a full Windows Authentication login: the LOGIN7 SSPI
// field carries an NTLMSSP NEGOTIATE, the server answers with a CHALLENGE in a
// TDS SSPI message, and the AUTHENTICATE that follows is recorded as a
// crackable NetNTLMv2 line.
func TestMSSQLNTLM(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, mssqlNTLMLogin(smbTestNegotiateToken()))); err != nil {
		t.Fatalf("write login7: %s", err)
	}

	typ, challenge := mssqlReadResponse(t, conn)
	if typ != mssqlPktSSPI {
		t.Fatalf("response type 0x%02x, want 0x%02x (SSPI)", typ, mssqlPktSSPI)
	}
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("SSPI message is not an NTLM CHALLENGE: % x", challenge)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Errorf("challenge %x, want %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	const user, domain, ws, password = "victim", "CORP", "WS01", "Summer2024!"
	blob := ntlmTestV2Blob(smbTestTargetInfo(t, challenge), false)
	proof := ntlmTestV2Proof(password, user, domain, NTLMConf.Challenge[:], blob)
	nt := append(append([]byte(nil), proof...), blob...)
	auth := ntlmTestAuthMsg(user, domain, ws, nil, nt, nil, 0)

	if _, err := conn.Write(mssqlPacket(mssqlPktSSPI, 0x01, auth)); err != nil {
		t.Fatalf("write sspi: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	mssqlCheckError(t, typ, msg, 18456, `Login failed for user 'CORP\victim'.`)

	rec := mssqlWaitCred(t, got)
	wantLine := fmt.Sprintf("%s::%s:%x:%x:%x", user, domain, NTLMConf.Challenge[:], proof, blob)
	want := map[string]string{
		"_proto":       "mssql",
		"method":       "NTLMSSP",
		"username":     user,
		"domain":       domain,
		"workstation":  ws,
		"password":     "",
		"ntlm_version": "v2",
		"hashcat":      wantLine,
		"hashcat_mode": "5600",
		"hostname":     "CORP-PC",
		"app_name":     "SSMS",
		"server_name":  "sql01.corp.test",
		"database":     "master",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
	if rec["client_os_version"] != "10.0.19043" {
		t.Errorf("client_os_version %q, want the version from the AUTHENTICATE", rec["client_os_version"])
	}
}

// TestMSSQLNTLMv1 covers a client that answers with a 24-byte NTLMv1 response,
// which is hashcat mode 5500 keyed on the workstation name.
func TestMSSQLNTLMv1(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, mssqlNTLMLogin(smbTestNegotiateToken()))); err != nil {
		t.Fatalf("write login7: %s", err)
	}
	if typ, _ := mssqlReadResponse(t, conn); typ != mssqlPktSSPI {
		t.Fatalf("response type 0x%02x, want 0x%02x (SSPI)", typ, mssqlPktSSPI)
	}

	nt := ntlmTestV1Response("Password1", NTLMConf.Challenge[:])
	lm := bytes.Repeat([]byte{0xcc}, 24)
	auth := ntlmTestAuthMsg("legacy", "", "OLDBOX", lm, nt, nil, 0)
	if _, err := conn.Write(mssqlPacket(mssqlPktSSPI, 0x01, auth)); err != nil {
		t.Fatalf("write sspi: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	mssqlCheckError(t, typ, msg, 18456, "Login failed for user 'legacy'.")

	rec := mssqlWaitCred(t, got)
	wantLine := fmt.Sprintf("legacy::OLDBOX:%x:%x:%x", lm, nt, NTLMConf.Challenge[:])
	if rec["hashcat"] != wantLine || rec["hashcat_mode"] != "5500" {
		t.Errorf("hashcat %q/%q, want %q/5500", rec["hashcat"], rec["hashcat_mode"], wantLine)
	}
	if rec["ntlm_version"] != "v1" || rec["domain"] != "" {
		t.Errorf("ntlm_version %q domain %q, want v1 and no domain", rec["ntlm_version"], rec["domain"])
	}
}

// TestMSSQLSSPI checks that an SSPI token which is not NTLMSSP — a Kerberos
// GSS-API blob here — is still recorded as an integrated-authentication
// attempt and refused, with no challenge sent.
func TestMSSQLSSPI(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	kerberos := append([]byte{0x60, 0x0e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02},
		make([]byte, 3)...)
	if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, mssqlNTLMLogin(kerberos))); err != nil {
		t.Fatalf("write login7: %s", err)
	}
	typ, msg := mssqlReadResponse(t, conn)
	mssqlCheckError(t, typ, msg, 18456, "Login failed for user ''.")

	rec := mssqlWaitCred(t, got)
	if rec["method"] != "sspi" {
		t.Errorf("method %q, want sspi", rec["method"])
	}
	if rec["password"] != "" || rec["username"] != "" {
		t.Errorf("SSPI login captured %q/%q, want empty", rec["username"], rec["password"])
	}
	if rec["sspi_length"] != "16" {
		t.Errorf("sspi_length %q, want 16", rec["sspi_length"])
	}
	if rec["hostname"] != "CORP-PC" || rec["app_name"] != "SSMS" || rec["server_name"] != "sql01.corp.test" {
		t.Errorf("unexpected fields: %v", rec)
	}
	if _, ok := rec["hashcat"]; ok {
		t.Errorf("non-NTLM SSPI token produced a hashcat line: %v", rec)
	}
}

// TestMSSQLSSPIBounds checks the SSPI security buffer against offsets and
// lengths that do not fit the message: a declared length longer than the
// LOGIN7 itself, the 64KB cbSSPILong escape, and an offset pointing inside the
// fixed header. None may yield a token, panic, or stall the parser.
func TestMSSQLSSPIBounds(t *testing.T) {
	le := binary.LittleEndian
	cases := []struct {
		name   string
		mangle func(p []byte)
	}{
		{"length past the end of the message", func(p []byte) { le.PutUint16(p[80:], 0xfffe) }},
		{"cbSSPILong escape", func(p []byte) {
			le.PutUint16(p[80:], 0xffff)
			le.PutUint32(p[90:], 1<<20)
		}},
		{"cbSSPILong just over the message cap", func(p []byte) {
			le.PutUint16(p[80:], 0xffff)
			le.PutUint32(p[90:], mssqlMaxSSPI+1)
		}},
		{"offset inside the fixed header", func(p []byte) { le.PutUint16(p[78:], 12) }},
		{"offset past the end of the message", func(p []byte) { le.PutUint16(p[78:], 0xfff0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			login := mssqlNTLMLogin(smbTestNegotiateToken())
			tc.mangle(login)
			l, err := mssqlParseLogin7(login)
			if err != nil {
				t.Fatalf("parse failed: %s", err)
			}
			if l.SSPIToken != nil {
				t.Errorf("token %x extracted from an out-of-bounds SSPI buffer", l.SSPIToken)
			}
			if !l.SSPI {
				t.Errorf("login should still be flagged as integrated authentication")
			}
		})
	}
}

// TestMSSQLNTLMTruncated feeds the SSPI exchange tokens that are not a usable
// AUTHENTICATE and checks nothing is recorded and nothing panics.
func TestMSSQLNTLMTruncated(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	cases := [][]byte{
		nil,                   // empty SSPI message
		[]byte("NTLMSSP\x00"), // signature only
		append([]byte("NTLMSSP\x00"), 3, 0, 0, 0),                              // AUTHENTICATE header and nothing else
		append(append([]byte("NTLMSSP\x00"), 3, 0, 0, 0), make([]byte, 60)...), // zeroed buffers
		[]byte("not a security token at all"),
	}
	for i, tok := range cases {
		conn := mssqlDial(t, addr)
		mssqlHandshake(t, conn)
		if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, mssqlNTLMLogin(smbTestNegotiateToken()))); err != nil {
			t.Fatalf("case %d: write login7: %s", i, err)
		}
		if typ, _ := mssqlReadResponse(t, conn); typ != mssqlPktSSPI {
			t.Fatalf("case %d: response type 0x%02x, want SSPI", i, typ)
		}
		conn.Write(mssqlPacket(mssqlPktSSPI, 0x01, tok))
		conn.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, conn)
		conn.Close()
		select {
		case rec := <-got:
			// A zeroed AUTHENTICATE parses into an empty identity with no
			// usable response; it must not produce a hashcat line.
			if rec["hashcat"] != "" {
				t.Errorf("case %d: unexpected credential %v", i, rec)
			}
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestMSSQLSSPIWithoutLogin7 checks an SSPI message that arrives before any
// LOGIN7 is dropped rather than answered.
func TestMSSQLSSPIWithoutLogin7(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)
	conn.Write(mssqlPacket(mssqlPktSSPI, 0x01, ntlmTestAuthMsg("a", "B", "C", nil, bytes.Repeat([]byte{1}, 48), nil, 0)))
	conn.(*net.TCPConn).CloseWrite()
	if b, _ := io.ReadAll(conn); len(b) != 0 {
		t.Errorf("server answered an unsolicited SSPI message: % x", b)
	}
	select {
	case rec := <-got:
		t.Errorf("unexpected record %v", rec)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestMSSQLMalformed sends truncated and bogus messages and checks the
// handler drops the connection without recording anything.
func TestMSSQLMalformed(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	cases := [][]byte{
		{0x12, 0x01, 0x00}, // truncated header
		{0x12, 0x01, 0x00, 0x0d, 0, 0, 1, 0, 0x00, 0xff, 0xff, 0x00, 0x09}, // bad option offsets
		mssqlPacket(mssqlPktLogin7, 0x01, make([]byte, 40)),                // short LOGIN7
		mssqlPacket(0x01, 0x01, nil),                                       // SQL batch before login
	}
	for i, in := range cases {
		conn := mssqlDial(t, addr)
		conn.Write(in)
		conn.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, conn)
		conn.Close()
		select {
		case rec := <-got:
			t.Errorf("case %d: unexpected record %v", i, rec)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestMSSQLLogin7HeaderOffsets checks that a string offset pointing inside the
// fixed header is rejected and that TDS 7.1 ignores the 7.2 header fields.
func TestMSSQLLogin7HeaderOffsets(t *testing.T) {
	login := mssqlTestLogin7(0x74000004, mssqlLogin7Fields{user: "sa", pw: "pw"})
	// Point the username at the TDS version field inside the header.
	binary.LittleEndian.PutUint16(login[40:], 4)
	l, err := mssqlParseLogin7(login)
	if err != nil {
		t.Fatalf("parse failed: %s", err)
	}
	if l.Username != "" {
		t.Errorf("username %q from an in-header offset, want empty", l.Username)
	}
	if l.Password != "pw" {
		t.Errorf("password %q, want pw", l.Password)
	}

	// A 7.1 header ends at 86 bytes; bytes at 86 and 90 are string data, not
	// the change password or long SSPI length.
	login = mssqlTestLogin7(0x71000001, mssqlLogin7Fields{user: "sa", pw: "pw"})
	l, err = mssqlParseLogin7(login)
	if err != nil {
		t.Fatalf("parse failed: %s", err)
	}
	if l.ChangePassword != "" || l.SSPI {
		t.Errorf("tds 7.1 parsed change password %q sspi %v", l.ChangePassword, l.SSPI)
	}
}

// mssqlLegacyLogin builds a TDS 4.2 login record the way FreeTDS tds_send_login does.
func mssqlLegacyLogin(host, user, pw, app, server string) []byte {
	var b []byte
	str := func(s string, n int) {
		f := make([]byte, n)
		copy(f, s)
		b = append(b, f...)
		b = append(b, byte(min(len(s), n)))
	}
	str(host, 30)
	str(user, 30)
	str(pw, 30)
	str("37876", 30)
	b = append(b, 0x03, 0x01, 0x06, 0x0a, 0x09, 0x01) // byte order
	b = append(b, 1, 0, 0)                            // bulk copy, padding
	b = binary.LittleEndian.AppendUint32(b, 512)
	b = append(b, 0, 0, 0)
	str(app, 30)
	str(server, 30)
	str("\x00"+string(rune(len(pw)))+pw, 255) // remote password for the default server
	b = append(b, 4, 2, 0, 0)                 // TDS 4.2
	str("DB-Library", 10)
	b = append(b, 0, 0, 0, 0)
	b = append(b, 0, 13, 17)
	str("us_english", 30)
	b = append(b, 0)    // suppress language
	b = append(b, 0, 0) // old secure
	b = append(b, 0)    // security flags
	b = append(b, make([]byte, 10)...)
	str("", 30) // charset
	b = append(b, 1)
	str("512", 6)
	return append(b, make([]byte, 8)...)
}

func TestMSSQLLegacyLogin(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	rec := mssqlLegacyLogin("WORKSTATION", "sa", "Secret123", "isql", "SQL01")
	if len(rec) != 572 {
		t.Fatalf("login record is %d bytes, want 572", len(rec))
	}
	conn := mssqlDial(t, addr)
	defer conn.Close()
	// Two 512-byte packets, as a client with the default packet size sends them.
	for off := 0; off < len(rec); {
		n := min(len(rec)-off, 504)
		status := byte(0)
		if off+n == len(rec) {
			status = 1
		}
		if _, err := conn.Write(mssqlPacket(0x02, status, rec[off:off+n])); err != nil {
			t.Fatal(err)
		}
		off += n
	}
	resp, _ := io.ReadAll(conn)
	if len(resp) < 9 || resp[0] != 0x04 || resp[8] != 0xaa || !strings.Contains(string(resp), "Login failed for user 'sa'.") {
		t.Fatalf("response %q", resp)
	}
	cred := mssqlWaitCred(t, got)
	want := map[string]string{
		"username": "sa", "password": "Secret123", "hostname": "WORKSTATION", "app_name": "isql",
		"server_name": "SQL01", "library": "DB-Library", "tds_version": "4.2", "client_pid": "37876",
		"language": "us_english", "packet_size": "512", "login_record": "tds4",
	}
	for k, v := range want {
		if cred[k] != v {
			t.Errorf("%s = %q, want %q", k, cred[k], v)
		}
	}
	if _, ok := cred["remote_password"]; ok {
		t.Errorf("remote password equal to the login password recorded twice")
	}
}
