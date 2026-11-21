package flamingo

import (
	"errors"
	"fmt"
	"sync"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// ConfMSRPC holds the configuration for an MSRPC capture server.
//
// The listener is gopacket's DCE/RPC server, which answers BIND and
// ALTER_CONTEXT, carries the NTLMSSP CHALLENGE back in the BIND_ACK auth
// verifier, and reads the AUTHENTICATE out of the AUTH3 that follows. It also
// answers IObjectExporter::ServerAlive2 and epmapper::ept_map so a DCOM client
// gets far enough to authenticate. Everything past that — the credential
// itself — is flamingo's NTLM core, through NTLMCapture.
type ConfMSRPC struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	capture      *NTLMCapture
	shutdown     bool
	m            sync.Mutex
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

	c.m.Lock()
	if c.shutdown {
		c.m.Unlock()
		return errors.New("msrpc is shut down")
	}
	c.capture = capture
	c.m.Unlock()

	if err := capture.Start(relay.NewRPCRelayServer(addr)); err != nil {
		return err
	}
	log.Debugf("msrpc is listening on %s", addr)
	return nil
}
