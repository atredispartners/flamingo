package flamingo

import (
	"errors"
	"sync"
)

// ConfWinRM holds the configuration for a WinRM capture server.
//
// WinRM is NTLM over HTTP on /wsman, so this listener is flamingo's own HTTP
// collector bound to 5985 and relabelled. That is not a shortcut: it is what
// the protocol is, and it means WinRM inherits the HTTP listener's NTLM
// handling, its relay seam, and its bounds checking rather than carrying a
// second implementation of the same exchange.
//
// What is captured is the credential, not a command shell. A client that
// authenticates and then tries to run something gets nothing useful back, by
// which point the hash is already recorded.
//
// This listener used to be built on gopacket's relay.NewWinRMRelayServer --
// itself a thin wrapper over that project's HTTP server. It was moved off it
// because that server parses attacker-supplied NTLM with arithmetic that
// panics where int is 32 bits, which made WinRM unavailable on flamingo's 386
// and arm builds. Owning the exchange removes that limitation.
type ConfWinRM struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// TLS serves WinRM over HTTPS on 5986 instead of plain HTTP on 5985.
	TLS     bool
	TLSName string
	TLSCert string
	TLSKey  string

	// Responder decides the challenge a victim is answered with and whether
	// it is told the logon succeeded. Nil -- the default -- is capture only.
	Responder NTLMResponder

	http     *ConfHTTP
	shutdown bool
	m        sync.Mutex
}

// NewConfWinRM creates a default configuration for the WinRM capture server.
func NewConfWinRM() *ConfWinRM {
	return &ConfWinRM{
		BindPort: 5985,
		BindHost: "[::]",
	}
}

// NewConfWinRMS creates a default configuration for WinRM over TLS.
func NewConfWinRMS() *ConfWinRM {
	return &ConfWinRM{
		BindPort: 5986,
		BindHost: "[::]",
		TLS:      true,
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfWinRM) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfWinRM) Shutdown() {
	c.m.Lock()
	inner := c.http
	if c.shutdown {
		c.m.Unlock()
		return
	}
	c.shutdown = true
	c.m.Unlock()

	if inner != nil {
		inner.Shutdown()
	}
}

// SpawnWinRM starts a WinRM capture server.
func SpawnWinRM(c *ConfWinRM) error {
	inner := NewConfHTTP()
	inner.BindPort = c.BindPort
	inner.BindHost = c.BindHost
	inner.RecordWriter = c.RecordWriter
	inner.AuthMode = "ntlm"
	inner.ProtoName = "winrm"
	inner.ChallengeAllMethods = true
	inner.RefuseAuth = true
	inner.tlsSuffix = "winrms"
	inner.Responder = c.Responder
	inner.TLS = c.TLS
	inner.TLSName = c.TLSName
	inner.TLSCert = c.TLSCert
	inner.TLSKey = c.TLSKey

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errWinRMShutdown
	}
	c.http = inner
	c.m.Unlock()

	return SpawnHTTP(inner)
}

// SpawnWinRMS starts a WinRM capture server on TLS. It is SpawnWinRM with TLS
// forced on, kept separate so the command line can start one of each.
func SpawnWinRMS(c *ConfWinRM) error {
	c.TLS = true
	return SpawnWinRM(c)
}

// errWinRMShutdown is returned when a listener is started after shutdown.
var errWinRMShutdown = errors.New("winrm is shut down")
