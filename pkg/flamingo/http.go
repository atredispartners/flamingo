package flamingo

import (
	ctx "context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfHTTP describes the options for a HTTP service
type ConfHTTP struct {
	BindPort     uint16
	BindHost     string
	BasicRealm   string
	RecordWriter *RecordWriter
	TLS          bool
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	server       *http.Server
	m            sync.Mutex
}

// IsShutdown checks to see if the service is shutting down
func (c *ConfHTTP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfHTTP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()

	if !c.shutdown {
		c.shutdown = true
		c.server.Shutdown(ctx.Background())
	}
}

// NewConfHTTP creates a default configuration for the HTTP capture server
func NewConfHTTP() *ConfHTTP {
	return &ConfHTTP{
		BindPort: 389,
		BindHost: "[::]",
	}
}

// SpawnHTTP starts a logging HTTP server
func SpawnHTTP(c *ConfHTTP) error {

	c.server = &http.Server{
		IdleTimeout:  60 * time.Second,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		Addr:         fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
	}
	c.server.Handler = httpHandler(c)

	// Handler normal listeners
	if !c.TLS {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
		if err != nil {
			return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
		}
		c.listener = listener
		go startHTTP(c)
		return nil
	}

	// Handle TLS listeners
	tlsConfig := tls.Config{ServerName: c.TLSName}
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
	if err != nil {
		return fmt.Errorf("failed to load tls cert for https on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	tlsConfig.Certificates = []tls.Certificate{kp}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort), &tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener
	go startHTTP(c)
	return nil
}

func startHTTP(c *ConfHTTP) {
	pname := "http"
	if c.TLS {
		pname = "https"
	}
	log.Debugf("%s is listening on %s:%d", pname, c.BindHost, c.BindPort)
	err := c.server.Serve(c.listener)
	if err != nil {
		log.Debugf("http server exited with error %s", err)
	}

	return
}

func httpHandler(c *ConfHTTP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// TODO: NLTMSSP Support
		// w.Header().Set("WWW-Authenticate", "Negotiate")

		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", c.BasicRealm))
		w.Header().Set("Server", "Microsoft-IIS/8.5")
		w.WriteHeader(401)

		if r.Header.Get("Authorization") != "" {
			if httpHandleBasicAuth(c, w, r) {
				return
			}
		}

		log.WithFields(log.Fields{
			"_server":       fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"_src":          r.RemoteAddr,
			"agent":         r.UserAgent(),
			"url":           r.RequestURI,
			"authorization": r.Header.Get("Authorization"),
		}).Debugf("access")
	}
}

func httpHandleBasicAuth(c *ConfHTTP, w http.ResponseWriter, r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) == 0 {
		return false
	}

	bits := strings.SplitN(auth, " ", 2)
	if len(bits) != 2 || len(bits[0]) == 0 || len(bits[1]) == 0 {
		return false
	}

	atype := strings.ToLower(bits[0])
	if atype != "basic" {
		return false
	}

	rawAuth, err := base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		return false
	}

	bits = strings.SplitN(string(rawAuth), ":", 2)
	if len(bits) != 2 || (len(bits[0]) == 0 && len(bits[1]) == 0) {
		return false
	}

	pname := "http"
	if c.TLS {
		pname = "https"
	}

	c.RecordWriter.Record(
		pname,
		r.RemoteAddr,
		map[string]string{
			"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"agent":    r.UserAgent(),
			"url":      r.RequestURI,
			"username": bits[0],
			"password": bits[1],
			"method":   "basic",
		},
	)

	return true
}

// TODO: NTLMSSP Support
/*
func httpHandleAuth(c *ConfHTTP, w http.ResponseWriter, r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) == 0 {
		return false
	}

	bits := strings.SplitN(auth, " ", 2)
	if len(bits) != 2 || len(bits[0]) == 0 || len(bits[1]) == 0 {
		return false
	}

	// Handle basic separately
	atype := strings.ToLower(bits[0])
	if atype == "basic" {
		httpHandleBasicAuth(c, w, r)
		return true
	}

	// Only process NTLM and Negotiate from here
	if atype != "ntlm" && atype != "negotiate" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(bits[1])
	if err != nil {
		return false
	}

	// Bail if there is no NTLMSSPHeader
	if !bytes.HasPrefix(decoded, httpNTLMSSPHeader) {
		return false
	}

	if len(decoded) <= len(httpNTLMSSPHeader)+1 {
		return false
	}


	// Check the "type" field of the NTLMSSP header
	switch decoded[8] {
	}

	return true

}
*/

var httpNTLMSSPHeader = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}
