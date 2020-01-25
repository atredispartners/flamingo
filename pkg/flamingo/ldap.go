package flamingo

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/atredispartners/flamingo/pkg/ldap"
	log "github.com/sirupsen/logrus"
)

// ConfLDAP describes the options for a LDAP service
type ConfLDAP struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	TLS          bool
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	server       *ldap.Server
	m            sync.Mutex
}

// IsShutdown checks to see if the service is shutting down
func (c *ConfLDAP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfLDAP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()

	if !c.shutdown {
		c.shutdown = true
		c.server.Quit <- true
	}
}

// Bind captures an LDAP bind request
func (c *ConfLDAP) Bind(bindDN string, pass string, conn net.Conn) (ldap.LDAPResultCode, error) {
	pname := "ldap"
	if c.TLS {
		pname = "ldaps"
	}

	c.RecordWriter.Record(
		pname,
		conn.RemoteAddr().String(),
		map[string]string{
			"username": bindDN,
			"password": pass,
			"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		},
	)
	return ldap.LDAPResultInvalidCredentials, nil
}

// NewConfLDAP creates a default configuration for the LDAP capture server
func NewConfLDAP() *ConfLDAP {
	return &ConfLDAP{
		BindPort: 389,
		BindHost: "[::]",
	}
}

// SpawnLDAP starts a logging LDAP server
func SpawnLDAP(c *ConfLDAP) error {

	s := ldap.NewServer()
	s.EnforceLDAP = true
	s.BindFunc("", c)
	c.server = s

	// Handler normal listeners
	if !c.TLS {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
		if err != nil {
			return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
		}
		c.listener = listener
		go startLDAP(c)
		return nil
	}

	// Handle TLS listeners
	tlsConfig := tls.Config{ServerName: c.TLSName}
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return fmt.Errorf("failed to load tls cert for ldaps on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	tlsConfig.Certificates = []tls.Certificate{kp}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort), &tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener
	go startLDAP(c)
	return nil
}

func startLDAP(c *ConfLDAP) {
	pname := "ldap"
	if c.TLS {
		pname = "ldaps"
	}
	log.Debugf("%s is listening on %s:%d", pname, c.BindHost, c.BindPort)
	err := c.server.Serve(c.listener)
	if err != nil {
		log.Debugf("ldap server exited with error %s", err)
	}

	return
}
