package flamingo

import (
	"bytes"
	"encoding/binary"
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
	// SSPI token offset and length share the slot after the attach DB file.
	le.PutUint16(hdr[76:], uint16(hdrLen+len(data)))
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

func TestMSSQLSSPI(t *testing.T) {
	addr, got, conf := mssqlTestServer(t)
	defer conf.Shutdown()

	conn := mssqlDial(t, addr)
	defer conn.Close()
	mssqlHandshake(t, conn)

	// An NTLMSSP negotiate blob stands in for the SSPI token.
	login := mssqlTestLogin7(0x74000004, mssqlLogin7Fields{
		host:   "CORP-PC",
		app:    "SSMS",
		server: "sql01.corp.test",
		lib:    "ODBC",
		db:     "master",
		sspi:   append([]byte("NTLMSSP\x00"), 1, 0, 0, 0, 0x97, 0x82, 0x08, 0xe2),
	})
	if _, err := conn.Write(mssqlPacket(mssqlPktLogin7, 0x01, login)); err != nil {
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
