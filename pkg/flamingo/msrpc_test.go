package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// The MSRPC tests drive the listener over a real socket with hand-built
// DCE/RPC PDUs, which is what a DCOM client actually sends: a BIND carrying an
// NTLMSSP NEGOTIATE in its authentication verifier, then an AUTH3 carrying the
// AUTHENTICATE.

// DCE/RPC packet types used by the tests, named independently of the
// implementation so a renamed constant cannot quietly make a test vacuous.
const (
	rpcTestPktRequest    = 0
	rpcTestPktFault      = 3
	rpcTestPktBind       = 11
	rpcTestPktBindAck    = 12
	rpcTestPktBindNak    = 13
	rpcTestPktAlterCtx   = 14
	rpcTestPktAlterCtxR  = 15
	rpcTestPktAuth3      = 16
	rpcTestAuthWinNT     = 10
	rpcTestAuthSPNEGO    = 9
	rpcTestFirstLast     = 0x03
	rpcTestAuthConnect   = 2
	rpcTestDrepLittle    = 0x10
	rpcTestDrepBig       = 0x00
	rpcTestContextAccept = 0
)

// rpcTestNDR20 is the NDR 2.0 transfer syntax, 8a885d04-1ceb-11c9-9fe8-
// 08002b104860 version 2, in the little-endian wire encoding.
var rpcTestNDR20 = []byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00,
}

// rpcTestObjectExporter is IObjectExporter, 99fcfec4-5260-101b-bbcb-
// 00aa0021347a version 0, the interface a DCOM client binds to on 135.
var rpcTestObjectExporter = []byte{
	0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
	0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
	0x00, 0x00, 0x00, 0x00,
}

// msrpcTestServer spawns an MSRPC collector on a free port and returns the
// address plus a channel that receives captured credential records.
func msrpcTestServer(t *testing.T) (string, chan map[string]string, *ConfMSRPC) {
	t.Helper()
	rw, got := captureTestWriter(t)

	conf := NewConfMSRPC()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw

	if err := SpawnMSRPC(conf); err != nil {
		t.Fatalf("SpawnMSRPC failed: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return fmt.Sprintf("127.0.0.1:%d", conf.BindPort), got, conf
}

func msrpcTestDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

// rpcTestPDU assembles a DCE/RPC PDU in the given byte order: the 16-byte
// common header, the body, and, when auth is non-empty, a security trailer
// plus the authentication verifier.
func rpcTestPDU(bo binary.ByteOrder, ptype byte, callID uint32, body, auth []byte) []byte {
	pdu := make([]byte, 16)
	pdu[0] = 5 // rpc_vers
	pdu[1] = 0 // rpc_vers_minor
	pdu[2] = ptype
	pdu[3] = rpcTestFirstLast
	if bo == binary.BigEndian {
		pdu[4] = rpcTestDrepBig
	} else {
		pdu[4] = rpcTestDrepLittle
	}
	bo.PutUint32(pdu[12:], callID)
	pdu = append(pdu, body...)
	if len(auth) > 0 {
		trailer := []byte{
			rpcTestAuthWinNT,   // auth_type: NTLMSSP
			rpcTestAuthConnect, // auth_level: connect
			0,                  // auth_pad_length
			0,                  // auth_reserved
			0, 0, 0, 0,         // auth_context_id
		}
		pdu = append(pdu, trailer...)
		pdu = append(pdu, auth...)
		bo.PutUint16(pdu[10:], uint16(len(auth)))
	}
	bo.PutUint16(pdu[8:], uint16(len(pdu)))
	return pdu
}

// rpcTestLE is the little-endian PDU builder, which is what every client but
// the big-endian test sends.
func rpcTestLE(ptype byte, callID uint32, body, auth []byte) []byte {
	return rpcTestPDU(binary.LittleEndian, ptype, callID, body, auth)
}

// rpcTestBindBody is a BIND body offering one presentation context with the
// given transfer syntaxes, NDR 2.0 when none are named.
func rpcTestBindBody(abstract []byte, syntaxes ...[]byte) []byte {
	if len(syntaxes) == 0 {
		syntaxes = [][]byte{rpcTestNDR20}
	}
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[0:], 5840) // max_xmit_frag
	binary.LittleEndian.PutUint16(body[2:], 5840) // max_recv_frag
	binary.LittleEndian.PutUint32(body[4:], 0)    // assoc_group_id
	body[8] = 1                                   // num_ctx_items

	ctx := make([]byte, 4)
	binary.LittleEndian.PutUint16(ctx[0:], 0) // context id
	ctx[2] = byte(len(syntaxes))              // transfer syntax count
	ctx = append(ctx, abstract...)
	for _, s := range syntaxes {
		ctx = append(ctx, s...)
	}
	return append(body, ctx...)
}

// rpcTestRecv reads one PDU, using the fragment length in the header.
func rpcTestRecv(t *testing.T, conn net.Conn, bo binary.ByteOrder) []byte {
	t.Helper()
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reading a PDU header: %s", err)
	}
	n := int(bo.Uint16(hdr[8:]))
	if n < 16 || n > 65536 {
		t.Fatalf("implausible fragment length %d", n)
	}
	pdu := make([]byte, n)
	copy(pdu, hdr)
	if n > 16 {
		if _, err := io.ReadFull(conn, pdu[16:]); err != nil {
			t.Fatalf("reading a PDU body: %s", err)
		}
	}
	return pdu
}

// rpcTestVerifier returns the authentication verifier of a PDU, located the
// way a client locates it: from auth_length and the end of the fragment. It
// fails the test when the lengths flamingo wrote do not add up, which is the
// point — FindNTLMSSP would find a challenge in a PDU whose header lied.
func rpcTestVerifier(t *testing.T, pdu []byte, bo binary.ByteOrder) []byte {
	t.Helper()
	if len(pdu) < 16 {
		t.Fatalf("PDU is %d bytes", len(pdu))
	}
	authLen := int(bo.Uint16(pdu[10:12]))
	if authLen == 0 {
		t.Fatal("the PDU carries no authentication verifier")
	}
	off := len(pdu) - authLen - 8
	if off < 16 {
		t.Fatalf("auth_length %d does not fit a %d byte PDU", authLen, len(pdu))
	}
	if pdu[off] != rpcTestAuthWinNT {
		t.Errorf("sec_trailer names authentication service %d, want NTLMSSP", pdu[off])
	}
	return pdu[off+8:]
}

// rpcTestAckResults parses the presentation context result list out of a
// BIND_ACK or ALTER_CONTEXT_RESP body.
func rpcTestAckResults(t *testing.T, pdu []byte, bo binary.ByteOrder) [][]byte {
	t.Helper()
	// max_xmit(2) + max_recv(2) + assoc_group(4), then port_any_t.
	off := 16 + 8
	if off+2 > len(pdu) {
		t.Fatalf("PDU is %d bytes, too short for a bind ack body", len(pdu))
	}
	off += 2 + int(bo.Uint16(pdu[off:off+2]))
	for off%4 != 0 {
		off++
	}
	if off+4 > len(pdu) {
		t.Fatal("the result list runs past the end of the PDU")
	}
	n := int(pdu[off])
	off += 4

	var out [][]byte
	for i := 0; i < n; i++ {
		if off+24 > len(pdu) {
			t.Fatalf("result %d runs past the end of the PDU", i)
		}
		out = append(out, pdu[off:off+24])
		off += 24
	}
	return out
}

// msrpcTestBindChallenge sends a BIND carrying an NTLMSSP NEGOTIATE and
// returns the CHALLENGE out of the BIND_ACK.
func msrpcTestBindChallenge(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	bind := rpcTestLE(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}
	ack := rpcTestRecv(t, conn, binary.LittleEndian)
	if ack[2] != rpcTestPktBindAck {
		t.Fatalf("reply is packet type %d, want BIND_ACK", ack[2])
	}
	challenge := rpcTestVerifier(t, ack, binary.LittleEndian)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("BIND_ACK verifier carries no CHALLENGE: %x", challenge)
	}
	return challenge
}

// msrpcTestProbe checks the listener is still answering by running a fresh
// bind on a new connection.
func msrpcTestProbe(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("the listener stopped accepting connections: %s", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	msrpcTestBindChallenge(t, conn)
}

// TestMSRPCCaptureNTLMv2 runs the whole exchange a DCOM client performs, and
// checks the recorded hash is the one computed over flamingo's fixed
// challenge.
func TestMSRPCCaptureNTLMv2(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestLE(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}

	ack := rpcTestRecv(t, conn, binary.LittleEndian)
	if ack[2] != rpcTestPktBindAck {
		t.Fatalf("reply is packet type %d, want BIND_ACK", ack[2])
	}
	if ack[1] != 0 || ack[0] != 5 {
		t.Errorf("BIND_ACK claims RPC version %d.%d", ack[0], ack[1])
	}
	if binary.LittleEndian.Uint32(ack[12:16]) != 1 {
		t.Errorf("BIND_ACK call_id is %d, want the request's 1", binary.LittleEndian.Uint32(ack[12:16]))
	}

	// The context the client offered is accepted and its transfer syntax
	// echoed, which is what makes a real client continue.
	results := rpcTestAckResults(t, ack, binary.LittleEndian)
	if len(results) != 1 {
		t.Fatalf("BIND_ACK carries %d context results, want 1", len(results))
	}
	if r := binary.LittleEndian.Uint16(results[0][0:2]); r != rpcTestContextAccept {
		t.Errorf("context result is %d, want acceptance", r)
	}
	if !bytes.Equal(results[0][4:24], rpcTestNDR20) {
		t.Errorf("accepted transfer syntax is %x, want NDR 2.0", results[0][4:24])
	}

	challenge := rpcTestVerifier(t, ack, binary.LittleEndian)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("BIND_ACK verifier carries no CHALLENGE: %x", challenge)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}
	if want := "1122334455667788"; hex.EncodeToString(challenge[24:32]) != want {
		t.Fatalf("CHALLENGE carries %x, want %s", challenge[24:32], want)
	}

	msg, proof, blob := captureTestV2Auth(t, challenge, "dcom", "CORP", "WS10", "Winter2025!")
	auth3 := rpcTestLE(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0}, msg)
	if _, err := conn.Write(auth3); err != nil {
		t.Fatalf("sending AUTH3: %s", err)
	}

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("dcom::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "5600" {
		t.Errorf("hashcat_mode is %q, want 5600", rec["hashcat_mode"])
	}
	if rec["_proto"] != "msrpc" {
		t.Errorf("_proto is %q, want msrpc", rec["_proto"])
	}
	if rec["_server"] != addr {
		t.Errorf("_server is %q, want %q", rec["_server"], addr)
	}
	if rec["ntlm_version"] != "v2" {
		t.Errorf("ntlm_version is %q, want v2", rec["ntlm_version"])
	}
	if rec["username"] != "dcom" || rec["domain"] != "CORP" || rec["workstation"] != "WS10" {
		t.Errorf("identity fields are %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}

	// Capture only: the logon is refused, which on the wire is a fault.
	fault := rpcTestRecv(t, conn, binary.LittleEndian)
	if fault[2] != rpcTestPktFault {
		t.Errorf("reply to AUTH3 is packet type %d, want FAULT", fault[2])
	}
}

// TestMSRPCCaptureNTLMv1 covers a client that answers with a bare 24-byte NT
// response, which cracks as hashcat mode 5500 rather than 5600.
func TestMSRPCCaptureNTLMv1(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)
	msrpcTestBindChallenge(t, conn)

	lm := bytes.Repeat([]byte{0x11}, 24)
	nt := bytes.Repeat([]byte{0x22}, 24)
	msg := ntlmTestAuthMsg("legacy", "CORP", "WS11", lm, nt, nil, 0)
	if _, err := conn.Write(rpcTestLE(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0}, msg)); err != nil {
		t.Fatalf("sending AUTH3: %s", err)
	}

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("legacy::WS11:%s:%s:%s", hex.EncodeToString(lm), hex.EncodeToString(nt),
		hex.EncodeToString(NTLMConf.Challenge[:]))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}
	if rec["hashcat_mode"] != "5500" {
		t.Errorf("hashcat_mode is %q, want 5500", rec["hashcat_mode"])
	}
	if rec["ntlm_version"] != "v1" {
		t.Errorf("ntlm_version is %q, want v1", rec["ntlm_version"])
	}
}

// TestMSRPCAlterContext covers the clients that open with ALTER_CONTEXT rather
// than BIND: the challenge comes back in an ALTER_CONTEXT_RESP.
func TestMSRPCAlterContext(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	alter := rpcTestLE(rpcTestPktAlterCtx, 4, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(alter); err != nil {
		t.Fatalf("sending ALTER_CONTEXT: %s", err)
	}
	resp := rpcTestRecv(t, conn, binary.LittleEndian)
	if resp[2] != rpcTestPktAlterCtxR {
		t.Fatalf("reply is packet type %d, want ALTER_CONTEXT_RESP", resp[2])
	}
	challenge := rpcTestVerifier(t, resp, binary.LittleEndian)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("ALTER_CONTEXT_RESP carries no CHALLENGE: %x", challenge)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, _, _ := captureTestV2Auth(t, challenge, "alter", "CORP", "WS12", "pass")
	if _, err := conn.Write(rpcTestLE(rpcTestPktAuth3, 4, []byte{0, 0, 0, 0}, msg)); err != nil {
		t.Fatalf("sending AUTH3: %s", err)
	}
	if rec := captureTestRecord(t, got); rec["username"] != "alter" {
		t.Errorf("username is %q, want alter", rec["username"])
	}
}

// TestMSRPCAuthenticateInAlterContext covers the clients that answer the
// challenge with an ALTER_CONTEXT carrying the AUTHENTICATE instead of an
// AUTH3.
func TestMSRPCAuthenticateInAlterContext(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)
	challenge := msrpcTestBindChallenge(t, conn)

	msg, _, _ := captureTestV2Auth(t, challenge, "second", "CORP", "WS13", "pass")
	alter := rpcTestLE(rpcTestPktAlterCtx, 1, rpcTestBindBody(rpcTestObjectExporter), msg)
	if _, err := conn.Write(alter); err != nil {
		t.Fatalf("sending ALTER_CONTEXT: %s", err)
	}
	if rec := captureTestRecord(t, got); rec["username"] != "second" {
		t.Errorf("username is %q, want second", rec["username"])
	}
}

// TestMSRPCBigEndianDrep runs the whole exchange with the data representation
// field naming big-endian integers, which the header fields and the reply have
// to honour even though no common client sends it.
func TestMSRPCBigEndianDrep(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestPDU(binary.BigEndian, rpcTestPktBind, 0x01020304,
		rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}

	ack := rpcTestRecv(t, conn, binary.BigEndian)
	if ack[2] != rpcTestPktBindAck {
		t.Fatalf("reply is packet type %d, want BIND_ACK", ack[2])
	}
	if ack[4] != rpcTestDrepBig {
		t.Errorf("reply drep is 0x%02x, want the request's big-endian 0x00", ack[4])
	}
	if id := binary.BigEndian.Uint32(ack[12:16]); id != 0x01020304 {
		t.Errorf("reply call_id is 0x%08x, want 0x01020304", id)
	}
	// A little-endian reader would see a wildly different fragment length,
	// which is the whole point of honouring drep.
	if binary.LittleEndian.Uint16(ack[8:10]) == uint16(len(ack)) {
		t.Error("the reply fragment length was written little-endian")
	}

	challenge := rpcTestVerifier(t, ack, binary.BigEndian)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("BIND_ACK carries no CHALLENGE: %x", challenge)
	}
	// NTLM itself is little-endian regardless of the RPC data representation.
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, proof, blob := captureTestV2Auth(t, challenge, "bigend", "CORP", "WS14", "pass")
	auth3 := rpcTestPDU(binary.BigEndian, rpcTestPktAuth3, 0x01020304, []byte{0, 0, 0, 0}, msg)
	if _, err := conn.Write(auth3); err != nil {
		t.Fatalf("sending AUTH3: %s", err)
	}

	rec := captureTestRecord(t, got)
	want := fmt.Sprintf("bigend::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != want {
		t.Errorf("hashcat line is %q, want %q", rec["hashcat"], want)
	}

	fault := rpcTestRecv(t, conn, binary.BigEndian)
	if fault[2] != rpcTestPktFault {
		t.Errorf("reply to AUTH3 is packet type %d, want FAULT", fault[2])
	}
}

// TestMSRPCBindWithoutAuth checks a bind that carries no authentication
// verifier is refused with a BIND_NAK rather than left open. flamingo carries
// no calls, so an unauthenticated association is of no use to either side.
func TestMSRPCBindWithoutAuth(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestLE(rpcTestPktBind, 7, rpcTestBindBody(rpcTestObjectExporter), nil)
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}
	nak := rpcTestRecv(t, conn, binary.LittleEndian)
	if nak[2] != rpcTestPktBindNak {
		t.Fatalf("reply is packet type %d, want BIND_NAK", nak[2])
	}
	if binary.LittleEndian.Uint32(nak[12:16]) != 7 {
		t.Errorf("BIND_NAK call_id is %d, want the request's 7", binary.LittleEndian.Uint32(nak[12:16]))
	}

	select {
	case rec := <-got:
		t.Errorf("an unauthenticated bind produced a credential: %v", rec)
	case <-time.After(100 * time.Millisecond):
	}
	msrpcTestProbe(t, addr)
}

// TestMSRPCUnsupportedAuthType checks a BIND carrying something other than
// NTLMSSP is refused cleanly instead of hanging the connection.
func TestMSRPCUnsupportedAuthType(t *testing.T) {
	addr, _, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	negotiate := captureTestNegotiate()
	bind := rpcTestLE(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), negotiate)
	bind[len(bind)-len(negotiate)-8] = rpcTestAuthSPNEGO // sec_trailer auth_type
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}
	nak := rpcTestRecv(t, conn, binary.LittleEndian)
	if nak[2] != rpcTestPktBindNak {
		t.Errorf("reply is packet type %d, want BIND_NAK", nak[2])
	}
	msrpcTestProbe(t, addr)
}

// TestMSRPCUnsupportedPacketType checks a PDU this listener does not carry is
// faulted and the connection closed.
func TestMSRPCUnsupportedPacketType(t *testing.T) {
	addr, _, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	req := make([]byte, 8)
	binary.LittleEndian.PutUint16(req[6:], 5) // IObjectExporter::ServerAlive2
	if _, err := conn.Write(rpcTestLE(rpcTestPktRequest, 8, req, nil)); err != nil {
		t.Fatalf("sending REQUEST: %s", err)
	}
	resp := rpcTestRecv(t, conn, binary.LittleEndian)
	if resp[2] != rpcTestPktFault {
		t.Errorf("reply is packet type %d, want FAULT", resp[2])
	}
	msrpcTestProbe(t, addr)
}

// msrpcTestWideSecBuf rewrites the security buffer at off so its offset sits
// just below 2^32. This is the exact shape that panics gopacket's
// relay.extractNTLMType3Info where int is 32 bits: the bounds check converts
// the offset to a negative int, passes, and the slice that follows uses the
// raw uint32. flamingo has to decode it as out of bounds and carry on.
func msrpcTestWideSecBuf(msg []byte, off int) []byte {
	out := append([]byte(nil), msg...)
	binary.LittleEndian.PutUint16(out[off:], 0xfff0)   // len
	binary.LittleEndian.PutUint16(out[off+2:], 0xfff0) // max len
	binary.LittleEndian.PutUint32(out[off+4:], 0xfffffff0)
	return out
}

// TestMSRPCWideSecurityBufferOffsets is the case this whole listener exists
// for. Each AUTHENTICATE carries a security buffer whose offset is near 2^32;
// none of them may panic the process, and the listener has to keep serving.
func TestMSRPCWideSecurityBufferOffsets(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)

	base := ntlmTestAuthMsg("crash", "CORP", "WS20", nil, bytes.Repeat([]byte{0x33}, 24), nil, 0)

	cases := []struct {
		name string
		off  int // security buffer header offset inside the AUTHENTICATE
	}{
		{"lm response", 12},
		{"nt response", 20},
		{"domain", 28},
		{"username", 36},
		{"workstation", 44},
		{"session key", 52},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := msrpcTestDial(t, addr)
			msrpcTestBindChallenge(t, conn)

			msg := msrpcTestWideSecBuf(base, tc.off)
			if _, err := conn.Write(rpcTestLE(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0}, msg)); err != nil {
				t.Fatalf("sending AUTH3: %s", err)
			}

			// The message is otherwise well formed, so it is still decoded
			// and recorded: the out of bounds buffer comes back empty and
			// everything else survives. What must not happen is a panic on a
			// goroutine no recover() of ours can reach.
			rec := captureTestRecord(t, got)
			switch tc.off {
			case 20:
				if rec["hashcat"] != "" {
					t.Errorf("an out of bounds NT response produced %q", rec["hashcat"])
				}
				if rec["ntlm_version"] != "none" {
					t.Errorf("ntlm_version is %q, want none", rec["ntlm_version"])
				}
			case 28:
				if rec["domain"] != "" {
					t.Errorf("an out of bounds domain decoded as %q", rec["domain"])
				}
				if rec["username"] != "crash" {
					t.Errorf("username is %q, want crash", rec["username"])
				}
			case 36:
				if rec["username"] != "" {
					t.Errorf("an out of bounds username decoded as %q", rec["username"])
				}
			case 44:
				if rec["workstation"] != "" {
					t.Errorf("an out of bounds workstation decoded as %q", rec["workstation"])
				}
			default:
				if rec["username"] != "crash" {
					t.Errorf("username is %q, want crash", rec["username"])
				}
			}

			conn.Close()
			msrpcTestProbe(t, addr)
		})
	}
}

// TestMSRPCMalformed throws rubbish at the listener. Nothing may panic or
// hang, no credential may be invented, and the listener has to still serve the
// next connection after every single case.
func TestMSRPCMalformed(t *testing.T) {
	addr, got, conf := msrpcTestServer(t)
	conf.capture.Timeout = 500 * time.Millisecond

	negotiate := captureTestNegotiate()
	bindBody := rpcTestBindBody(rpcTestObjectExporter)

	// wideOffsetAuth is a valid AUTHENTICATE except that its domain security
	// buffer points near 2^32, delivered without a preceding bind.
	wideOffsetAuth := msrpcTestWideSecBuf(
		ntlmTestAuthMsg("ghost", "CORP", "WS", nil, make([]byte, 24), nil, 0), 28)

	cases := []struct {
		name string
		send []byte
	}{
		{"empty", nil},
		{"one byte", []byte{5}},
		{"truncated header", []byte{5, 0, 11, 3, 0x10, 0, 0, 0, 0x48, 0, 0, 0, 1, 0, 0}},
		{"wrong rpc version", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			pdu[0] = 4
			return pdu
		}()},
		{"unknown data representation", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			pdu[4] = 0x70
			return pdu
		}()},
		{"frag length below the header", append([]byte{5, 0, 11, 3, 0x10, 0, 0, 0, 2, 0}, make([]byte, 6)...)},
		{"frag length beyond the limit", append([]byte{5, 0, 11, 3, 0x10, 0, 0, 0, 0xff, 0xff}, make([]byte, 6)...)},
		{"frag length lying about the body", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			binary.LittleEndian.PutUint16(pdu[8:], uint16(len(pdu)+64))
			return pdu
		}()},
		{"frag length shorter than the body", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			binary.LittleEndian.PutUint16(pdu[8:], 20)
			return pdu
		}()},
		{"auth length past the end", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			binary.LittleEndian.PutUint16(pdu[10:], 0xfff0)
			return pdu
		}()},
		{"auth length one byte too long", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			binary.LittleEndian.PutUint16(pdu[10:], uint16(len(pdu)-16-8+1))
			return pdu
		}()},
		{"auth length is the whole fragment", func() []byte {
			pdu := rpcTestLE(rpcTestPktBind, 1, bindBody, negotiate)
			binary.LittleEndian.PutUint16(pdu[10:], uint16(len(pdu)))
			return pdu
		}()},
		{"zero length verifier with a trailer", func() []byte {
			// A bind whose body ends in a sec_trailer but whose auth_length
			// is zero: there is no verifier to read.
			body := append(append([]byte(nil), bindBody...),
				rpcTestAuthWinNT, rpcTestAuthConnect, 0, 0, 0, 0, 0, 0)
			return rpcTestLE(rpcTestPktBind, 1, body, nil)
		}()},
		{"bind claiming 200 contexts", func() []byte {
			body := append([]byte(nil), bindBody...)
			body[8] = 200
			return rpcTestLE(rpcTestPktBind, 1, body, negotiate)
		}()},
		{"context claiming 200 transfer syntaxes", func() []byte {
			body := append([]byte(nil), bindBody...)
			body[14] = 200 // n_transfer_syn of the first context item
			return rpcTestLE(rpcTestPktBind, 1, body, negotiate)
		}()},
		{"bind body truncated to nothing", rpcTestLE(rpcTestPktBind, 1, nil, negotiate)},
		{"bind whose auth data is not NTLMSSP", rpcTestLE(rpcTestPktBind, 1, bindBody,
			[]byte("not an ntlm token at all"))},
		{"bind with a one byte verifier", rpcTestLE(rpcTestPktBind, 1, bindBody, []byte{0x4e})},
		{"bind carrying an NTLM CHALLENGE", rpcTestLE(rpcTestPktBind, 1, bindBody,
			NTLMChallengeMessage(0))},
		{"bind carrying an unknown NTLM message type", func() []byte {
			msg := append([]byte(nil), captureTestNegotiate()...)
			binary.LittleEndian.PutUint32(msg[8:], 99)
			return rpcTestLE(rpcTestPktBind, 1, bindBody, msg)
		}()},
		{"auth3 before any bind", rpcTestLE(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0},
			ntlmTestAuthMsg("ghost", "CORP", "WS", nil, make([]byte, 24), nil, 0))},
		{"auth3 with a wide security buffer and no bind", rpcTestLE(rpcTestPktAuth3, 1,
			[]byte{0, 0, 0, 0}, wideOffsetAuth)},
		{"auth3 with no verifier", rpcTestLE(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0}, nil)},
		{"unknown packet type", rpcTestLE(99, 1, make([]byte, 8), nil)},
		{"alter context with no verifier", rpcTestLE(rpcTestPktAlterCtx, 1, bindBody, nil)},
		{"http request", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"smb negotiate", []byte{0x00, 0x00, 0x00, 0x54, 0xff, 'S', 'M', 'B', 0x72}},
		{"random bytes", bytes.Repeat([]byte{0xa5}, 128)},
		{"header repeated forever", bytes.Repeat([]byte{5, 0, 11, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0}, 16)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %s", err)
			}
			defer conn.Close()
			// A short deadline: the point is that nothing panics and the
			// listener survives, not how long an idle socket lingers.
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			conn.Write(tc.send)
			io.Copy(io.Discard, conn)
			conn.Close()

			// Every case, not just the last: a listener that dies on input
			// three would otherwise be masked by the cases after it.
			msrpcTestProbe(t, addr)
		})
	}

	select {
	case rec := <-got:
		t.Errorf("malformed input produced a credential: %v", rec)
	default:
	}
}

// TestMSRPCPDULimit checks a client that binds and then talks without ever
// authenticating is dropped after a bounded number of PDUs.
func TestMSRPCPDULimit(t *testing.T) {
	addr, _, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	// A bind with no verifier is naked and closed, so send the one PDU type
	// that keeps the loop going: repeated binds carrying a NEGOTIATE. The
	// second is a protocol error, so the connection ends well inside the cap.
	bind := rpcTestLE(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	for i := 0; i < msrpcMaxPDUs+4; i++ {
		if _, err := conn.Write(bind); err != nil {
			break
		}
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Error("the listener never dropped a client that would not authenticate")
		}
	}
}

// TestMSRPCReadPDUBounds exercises the header parser directly, including the
// lengths that have to be refused before anything is allocated for them.
func TestMSRPCReadPDUBounds(t *testing.T) {
	hdr := func(mutate func([]byte)) []byte {
		h := []byte{5, 0, rpcTestPktBind, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0}
		mutate(h)
		return h
	}

	bad := []struct {
		name string
		pdu  []byte
	}{
		{"version 4", hdr(func(h []byte) { h[0] = 4 })},
		{"drep 0x70", hdr(func(h []byte) { h[4] = 0x70 })},
		{"frag length 15", hdr(func(h []byte) { binary.LittleEndian.PutUint16(h[8:], 15) })},
		{"frag length beyond the cap", hdr(func(h []byte) {
			binary.LittleEndian.PutUint16(h[8:], uint16(msrpcMaxFrag+1))
		})},
		{"auth length with no room", hdr(func(h []byte) {
			binary.LittleEndian.PutUint16(h[8:], 32)
			binary.LittleEndian.PutUint16(h[10:], 32)
		})},
		{"auth length 0xfff0", hdr(func(h []byte) {
			binary.LittleEndian.PutUint16(h[8:], 64)
			binary.LittleEndian.PutUint16(h[10:], 0xfff0)
		})},
	}
	for _, tc := range bad {
		if _, err := msrpcReadPDU(bytes.NewReader(tc.pdu)); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}

	// A big-endian header is read with big-endian lengths.
	be := []byte{5, 0, rpcTestPktBind, 3, 0x00, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 9}
	be = append(be, make([]byte, 8)...)
	p, err := msrpcReadPDU(bytes.NewReader(be))
	if err != nil {
		t.Fatalf("a big-endian header was refused: %s", err)
	}
	if len(p.raw) != 24 {
		t.Errorf("read %d bytes, want 24", len(p.raw))
	}
	if p.callID != 9 {
		t.Errorf("call_id is %d, want 9", p.callID)
	}
	if _, _, _, _, err := p.verifier(); err == nil {
		t.Error("a PDU with no verifier reported one")
	}
}

// TestMSRPCDisconnectMidExchange is the goroutine-leak case that matters in
// practice: a client that negotiates and then drops. The adapter's victim is
// parked on the rendezvous with no timeout of its own, so the listener has to
// be what releases it.
func TestMSRPCDisconnectMidExchange(t *testing.T) {
	addr, _, conf := msrpcTestServer(t)
	conf.capture.Timeout = 200 * time.Millisecond

	settle(t, 0)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %s", err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		bind := rpcTestLE(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
		if _, err := conn.Write(bind); err != nil {
			t.Fatalf("sending BIND: %s", err)
		}
		if i%2 == 0 {
			// Read the BIND_ACK first, then vanish before AUTH3.
			rpcTestRecv(t, conn, binary.LittleEndian)
		}
		conn.Close()
	}

	conf.Shutdown()
	settle(t, before)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines went from %d to %d across 20 abandoned exchanges", before, after)
	}
}

// TestMSRPCShutdown checks the listener stops promptly, stops listening, and
// tolerates being shut down twice.
func TestMSRPCShutdown(t *testing.T) {
	addr, _, conf := msrpcTestServer(t)
	msrpcTestDial(t, addr)

	start := time.Now()
	conf.Shutdown()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Shutdown took %s", elapsed)
	}
	if !conf.IsShutdown() {
		t.Error("IsShutdown is false after Shutdown")
	}
	conf.Shutdown()

	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("the port is still accepting connections after Shutdown")
	}
}

// TestMSRPCSpawnAfterShutdown checks a listener that was shut down before it
// was spawned does not bind.
func TestMSRPCSpawnAfterShutdown(t *testing.T) {
	rw, _ := captureTestWriter(t)
	conf := NewConfMSRPC()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = captureTestPort(t)
	conf.RecordWriter = rw
	conf.Shutdown()

	if err := SpawnMSRPC(conf); err == nil {
		t.Fatal("spawning an already shut down listener succeeded")
	}
	if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", conf.BindPort), time.Second); err == nil {
		conn.Close()
		t.Error("the port was bound anyway")
	}
}

func TestNewConfMSRPC(t *testing.T) {
	conf := NewConfMSRPC()
	if conf.BindPort != 135 {
		t.Errorf("default port is %d, want 135", conf.BindPort)
	}
	if conf.BindHost != "[::]" {
		t.Errorf("default host is %q, want [::]", conf.BindHost)
	}
	if conf.IsShutdown() {
		t.Error("a fresh configuration reports itself shut down")
	}
}
