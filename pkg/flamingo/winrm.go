package flamingo

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// ConfWinRM holds the configuration for a WinRM capture server.
//
// WinRM is NTLM over HTTP on /wsman, and that is exactly as far as this goes:
// upstream's WinRM server is a thin wrapper over its HTTP server with no WSMan
// SOAP parsing on the server side, so what is captured is the credential, not
// a command shell. A client that authenticates and then tries to run something
// gets nothing useful back, by which point the hash is already recorded.
type ConfWinRM struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	capture      *NTLMCapture
	shutdown     bool
	m            sync.Mutex
}

// NewConfWinRM creates a default configuration for the WinRM capture server.
func NewConfWinRM() *ConfWinRM {
	return &ConfWinRM{
		BindPort: 5985,
		BindHost: "[::]",
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

// SpawnWinRM starts a logging WinRM server, normally on port 5985.
func SpawnWinRM(c *ConfWinRM) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	capture := NewNTLMCapture("winrm", addr, c.RecordWriter)

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errors.New("winrm is shut down")
	}
	c.capture = capture
	c.m.Unlock()

	// Each listener gets a Config of its own and never shares one: upstream
	// writes relayed-session fields on it from concurrent handlers without a
	// lock, so a shared Config is a data race.
	if err := capture.Start(relay.NewWinRMRelayServer(addr, &relay.Config{})); err != nil {
		return err
	}
	log.Debugf("winrm is listening on %s", addr)
	return nil
}

// ConfWinRMS holds the configuration for a WinRM-over-TLS capture server.
//
// TLSCertFile and TLSKeyFile are paths because that is what upstream's HTTPS
// server takes; left empty it generates a self-signed certificate of its own,
// which is not the certificate flamingo's other TLS listeners present.
type ConfWinRMS struct {
	BindPort     uint16
	BindHost     string
	TLSCertFile  string
	TLSKeyFile   string
	RecordWriter *RecordWriter
	capture      *NTLMCapture
	shutdown     bool
	m            sync.Mutex
}

// NewConfWinRMS creates a default configuration for the WinRM-over-TLS
// capture server.
func NewConfWinRMS() *ConfWinRMS {
	return &ConfWinRMS{
		BindPort: 5986,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfWinRMS) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfWinRMS) Shutdown() {
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

// SpawnWinRMS starts a logging WinRM-over-TLS server, normally on port 5986.
func SpawnWinRMS(c *ConfWinRMS) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	capture := NewNTLMCapture("winrms", addr, c.RecordWriter)

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errors.New("winrms is shut down")
	}
	c.capture = capture
	c.m.Unlock()

	// One Config per listener, never shared (see SpawnWinRM).
	conf := &relay.Config{CertFile: c.TLSCertFile, KeyFile: c.TLSKeyFile}
	server, err := relay.NewWinRMSRelayServer(addr, conf)
	if err != nil {
		return err
	}
	if err := capture.Start(server); err != nil {
		return err
	}
	log.Debugf("winrms is listening on %s", addr)
	return nil
}
