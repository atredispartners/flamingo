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

// DCE/RPC packet types used by the tests.
const (
	rpcTestPktRequest  = 0
	rpcTestPktBind     = 11
	rpcTestPktBindAck  = 12
	rpcTestPktBindNak  = 13
	rpcTestPktFault    = 3
	rpcTestPktAuth3    = 16
	rpcTestAuthWinNT   = 10
	rpcTestFirstLast   = 0x03
	rpcTestAuthConnect = 2
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

// rpcTestPDU assembles a DCE/RPC PDU: the 16-byte common header, the body,
// and, when auth is non-empty, a security trailer plus the authentication
// verifier.
func rpcTestPDU(ptype byte, callID uint32, body, auth []byte) []byte {
	pdu := make([]byte, 16)
	pdu[0] = 5 // rpc_vers
	pdu[1] = 0 // rpc_vers_minor
	pdu[2] = ptype
	pdu[3] = rpcTestFirstLast
	pdu[4] = 0x10 // little-endian, ASCII, IEEE
	binary.LittleEndian.PutUint32(pdu[12:], callID)
	pdu = append(pdu, body...)
	if len(auth) > 0 {
		pdu = append(pdu,
			rpcTestAuthWinNT,   // auth_type: NTLMSSP
			rpcTestAuthConnect, // auth_level: connect
			0,                  // auth_pad_length
			0,                  // auth_reserved
			0, 0, 0, 0,         // auth_context_id
		)
		pdu = append(pdu, auth...)
		binary.LittleEndian.PutUint16(pdu[10:], uint16(len(auth)))
	}
	binary.LittleEndian.PutUint16(pdu[8:], uint16(len(pdu)))
	return pdu
}

// rpcTestBindBody is a BIND body offering one presentation context.
func rpcTestBindBody(abstract []byte) []byte {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint16(body[0:], 5840) // max_xmit_frag
	binary.LittleEndian.PutUint16(body[2:], 5840) // max_recv_frag
	binary.LittleEndian.PutUint32(body[4:], 0)    // assoc_group_id
	body[8] = 1                                   // num_ctx_items

	ctx := make([]byte, 4)
	binary.LittleEndian.PutUint16(ctx[0:], 0) // context id
	ctx[2] = 1                                // transfer syntax count
	ctx = append(ctx, abstract...)
	ctx = append(ctx, rpcTestNDR20...)
	return append(body, ctx...)
}

// rpcTestRecv reads one PDU, using the fragment length in the header.
func rpcTestRecv(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatalf("reading a PDU header: %s", err)
	}
	n := int(binary.LittleEndian.Uint16(hdr[8:]))
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

// TestMSRPCCaptureNTLMv2 runs the whole exchange a DCOM client performs, and
// checks the recorded hash is the one computed over flamingo's fixed
// challenge.
func TestMSRPCCaptureNTLMv2(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestPDU(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}

	ack := rpcTestRecv(t, conn)
	if ack[2] != rpcTestPktBindAck {
		t.Fatalf("reply is packet type %d, want BIND_ACK", ack[2])
	}
	challenge := FindNTLMSSP(ack)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("BIND_ACK carries no CHALLENGE: %x", ack)
	}
	if !bytes.Equal(challenge[24:32], NTLMConf.Challenge[:]) {
		t.Fatalf("CHALLENGE carries %x, want the configured %x", challenge[24:32], NTLMConf.Challenge[:])
	}

	msg, proof, blob := captureTestV2Auth(t, challenge, "dcom", "CORP", "WS10", "Winter2025!")
	auth3 := rpcTestPDU(rpcTestPktAuth3, 1, []byte{0, 0, 0, 0}, msg)
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
	if rec["username"] != "dcom" || rec["domain"] != "CORP" || rec["workstation"] != "WS10" {
		t.Errorf("identity fields are %q/%q/%q", rec["username"], rec["domain"], rec["workstation"])
	}

	// Capture only: the logon is refused, which on the wire is a fault.
	fault := rpcTestRecv(t, conn)
	if fault[2] != rpcTestPktFault {
		t.Errorf("reply to AUTH3 is packet type %d, want FAULT", fault[2])
	}
}

// TestMSRPCBindWithoutAuth checks that a client binding before it
// authenticates is answered rather than dropped, which is what gets a real
// DCOM client as far as the authenticated bind.
func TestMSRPCBindWithoutAuth(t *testing.T) {
	addr, _, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestPDU(rpcTestPktBind, 7, rpcTestBindBody(rpcTestObjectExporter), nil)
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}
	ack := rpcTestRecv(t, conn)
	if ack[2] != rpcTestPktBindAck {
		t.Fatalf("reply is packet type %d, want BIND_ACK", ack[2])
	}

	// IObjectExporter::ServerAlive2 is opnum 5. Upstream answers it so a
	// client probing the endpoint mapper keeps the connection going.
	req := make([]byte, 8)
	binary.LittleEndian.PutUint32(req[0:], 0) // alloc_hint
	binary.LittleEndian.PutUint16(req[4:], 0) // context id
	binary.LittleEndian.PutUint16(req[6:], 5) // opnum
	if _, err := conn.Write(rpcTestPDU(rpcTestPktRequest, 8, req, nil)); err != nil {
		t.Fatalf("sending REQUEST: %s", err)
	}
	resp := rpcTestRecv(t, conn)
	if resp[2] == rpcTestPktFault {
		t.Error("ServerAlive2 was faulted rather than answered")
	}
}

// TestMSRPCUnsupportedAuthType checks a BIND carrying something other than
// NTLMSSP is refused cleanly instead of hanging the connection.
func TestMSRPCUnsupportedAuthType(t *testing.T) {
	addr, _, _ := msrpcTestServer(t)
	conn := msrpcTestDial(t, addr)

	bind := rpcTestPDU(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	bind[len(bind)-len(captureTestNegotiate())-8] = 9 // auth_type: SPNEGO
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND: %s", err)
	}
	nak := rpcTestRecv(t, conn)
	if nak[2] != rpcTestPktBindNak {
		t.Errorf("reply is packet type %d, want BIND_NAK", nak[2])
	}
}

// TestMSRPCMalformed throws rubbish at the listener. Nothing may panic or
// hang, and the listener has to stay up for the next client.
func TestMSRPCMalformed(t *testing.T) {
	addr, got, _ := msrpcTestServer(t)

	cases := []struct {
		name string
		send []byte
	}{
		{"empty", nil},
		{"short header", []byte{5, 0, 11}},
		{"frag length below the header", append([]byte{5, 0, 11, 3, 0x10, 0, 0, 0, 2, 0}, make([]byte, 6)...)},
		{"frag length beyond the limit", append([]byte{5, 0, 11, 3, 0x10, 0, 0, 0, 0xff, 0xff}, make([]byte, 6)...)},
		{"bind claiming 200 contexts", func() []byte {
			body := rpcTestBindBody(rpcTestObjectExporter)
			body[8] = 200
			return rpcTestPDU(rpcTestPktBind, 1, body, nil)
		}()},
		{"bind with auth_length past the end", func() []byte {
			pdu := rpcTestPDU(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
			binary.LittleEndian.PutUint16(pdu[10:], 0xfff0)
			return pdu
		}()},
		{"bind whose auth data is not NTLMSSP", rpcTestPDU(rpcTestPktBind, 1,
			rpcTestBindBody(rpcTestObjectExporter), []byte("not an ntlm token at all"))},
		{"unknown packet type", rpcTestPDU(99, 1, make([]byte, 8), nil)},
		{"http request", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"random bytes", bytes.Repeat([]byte{0xa5}, 128)},
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
		})
	}

	select {
	case rec := <-got:
		t.Errorf("malformed input produced a credential: %v", rec)
	default:
	}

	// The listener is still serving.
	conn := msrpcTestDial(t, addr)
	bind := rpcTestPDU(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
	if _, err := conn.Write(bind); err != nil {
		t.Fatalf("sending BIND after the malformed run: %s", err)
	}
	ack := rpcTestRecv(t, conn)
	if ack[2] != rpcTestPktBindAck {
		t.Errorf("the listener stopped answering: packet type %d", ack[2])
	}
}

// TestMSRPCDisconnectMidExchange is the goroutine-leak case that matters in
// practice: a client that negotiates and then drops. Upstream's handler is
// parked on the rendezvous with no timeout of its own, so the adapter has to
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
		bind := rpcTestPDU(rpcTestPktBind, 1, rpcTestBindBody(rpcTestObjectExporter), captureTestNegotiate())
		if _, err := conn.Write(bind); err != nil {
			t.Fatalf("sending BIND: %s", err)
		}
		if i%2 == 0 {
			// Read the BIND_ACK first, then vanish before AUTH3.
			rpcTestRecv(t, conn)
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
