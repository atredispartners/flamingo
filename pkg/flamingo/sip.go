package flamingo

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// SIPNonce is the fixed Digest nonce offered in every 401 challenge. A
// static nonce (rather than a random one) means captured responses can be
// cracked offline with precomputed material, the same trade flamingo makes
// with its fixed NTLM and VNC challenges. The value is arbitrary but constant.
const SIPNonce = "1e3f7a9c5b2d8e40"

// SIP identity presented in replies and challenges.
const (
	sipServer = "Asterisk PBX 18.9.0"
	sipRealm  = "asterisk"
)

// sipHeaderNames maps lowercase and compact header names to the record and
// echo key used for the headers worth keeping from a request.
var sipHeaderNames = map[string]string{
	"via":                 "via",
	"v":                   "via",
	"from":                "from",
	"f":                   "from",
	"to":                  "to",
	"t":                   "to",
	"call-id":             "call-id",
	"i":                   "call-id",
	"cseq":                "cseq",
	"contact":             "contact",
	"m":                   "contact",
	"user-agent":          "user-agent",
	"authorization":       "authorization",
	"proxy-authorization": "proxy-authorization",
}

// sipEchoHeaders lists the request headers copied into every reply, with
// the wire casing to use for each.
var sipEchoHeaders = [][2]string{
	{"via", "Via"},
	{"from", "From"},
	{"to", "To"},
	{"call-id", "Call-ID"},
	{"cseq", "CSeq"},
}

// ConfSIP describes the options for a SIP capture service
type ConfSIP struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.PacketConn
	m            sync.Mutex
}

// IsShutdown checks to see if the service is shutting down
func (c *ConfSIP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfSIP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.listener != nil {
		c.listener.Close()
	}
}

// NewConfSIP creates a default configuration for the SIP capture server
func NewConfSIP() *ConfSIP {
	return &ConfSIP{
		BindPort: 5060,
		BindHost: "[::]",
	}
}

// SpawnSIP starts a logging SIP (UDP) server
func SpawnSIP(c *ConfSIP) error {
	listener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}
	c.listener = listener
	go sipStart(c)
	return nil
}

// sipStart reads datagrams until the service is shut down
func sipStart(c *ConfSIP) {
	log.Debugf("sip is listening on %s:%d", c.BindHost, c.BindPort)

	buff := make([]byte, 65535)
	for {
		if c.IsShutdown() {
			log.Debugf("sip server on %s:%d is shutting down", c.BindHost, c.BindPort)
			break
		}

		rlen, raddr, rerr := c.listener.ReadFrom(buff)
		if rerr != nil {
			continue
		}

		sipProcess(c, raddr, buff[0:rlen])
	}
}

// sipProcess handles one datagram, recovering from any decoder panic
func sipProcess(c *ConfSIP, raddr net.Addr, data []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("sip decoder panic with data %s: %q", hex.EncodeToString(data), r)
		}
	}()
	sipProcessData(c, raddr, data)
}

// sipProcessData answers a request as a PBX would: OPTIONS succeeds, ACK is
// silent, anything else is challenged for Digest credentials and refused
// (and recorded) once they arrive.
func sipProcessData(c *ConfSIP, raddr net.Addr, data []byte) {
	req := sipParseRequest(data)
	if req == nil {
		return
	}

	switch {
	case req.Method == "OPTIONS":
		c.listener.WriteTo(sipReply("200 OK", req,
			"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\n"+
				"Accept: application/sdp\r\n"+
				"Supported: replaces, timer\r\n"), raddr)
	case req.Method == "ACK":
		return
	case req.Auth != "":
		sipRecord(c, raddr, req)
		c.listener.WriteTo(sipReply("403 Forbidden", req, ""), raddr)
	default:
		c.listener.WriteTo(sipReply("401 Unauthorized", req,
			fmt.Sprintf("WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", algorithm=MD5\r\n", sipRealm, SIPNonce)), raddr)
	}
}

// sipRequest is a parsed SIP request datagram
type sipRequest struct {
	Method  string
	URI     string
	Headers map[string]string
	Auth    string
}

// sipParseRequest parses the request line and interesting headers of a SIP
// request, returning nil for responses and non-SIP data. Only the first
// occurrence of each header is kept.
func sipParseRequest(data []byte) *sipRequest {
	line, rest, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "SIP/2.") || strings.HasPrefix(fields[0], "SIP/") {
		return nil
	}

	req := &sipRequest{
		Method:  fields[0],
		URI:     fields[1],
		Headers: make(map[string]string),
	}

	last := ""
	for h := range strings.SplitSeq(rest, "\n") {
		h = strings.TrimRight(h, "\r")
		if h == "" {
			break
		}
		// Continuation line of the previous header
		if h[0] == ' ' || h[0] == '\t' {
			if last != "" {
				req.Headers[last] += " " + strings.TrimSpace(h)
			}
			continue
		}
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		name := sipHeaderNames[strings.ToLower(strings.TrimSpace(k))]
		if name == "" {
			last = ""
			continue
		}
		if _, dup := req.Headers[name]; dup {
			last = ""
			continue
		}
		req.Headers[name] = strings.TrimSpace(v)
		last = name
	}

	if v := req.Headers["authorization"]; v != "" {
		req.Auth = v
	} else if v := req.Headers["proxy-authorization"]; v != "" {
		req.Auth = v
	}
	return req
}

// sipReply builds a response that echoes the request's dialog headers,
// tags the To header, and appends any extra headers before the server line.
func sipReply(status string, req *sipRequest, extra string) []byte {
	var b strings.Builder
	b.WriteString("SIP/2.0 " + status + "\r\n")
	for _, h := range sipEchoHeaders {
		v := req.Headers[h[0]]
		if v == "" {
			continue
		}
		if h[0] == "to" && !strings.Contains(v, "tag=") {
			v += ";tag=" + sipTag()
		}
		b.WriteString(h[1] + ": " + v + "\r\n")
	}
	b.WriteString(extra)
	b.WriteString("Server: " + sipServer + "\r\nContent-Length: 0\r\n\r\n")
	return []byte(b.String())
}

// sipTag returns a short random dialog tag for the To header
func sipTag() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// sipRecord writes a credential record for a request carrying Digest
// credentials
func sipRecord(c *ConfSIP, raddr net.Addr, req *sipRequest) {
	d := sipParseDigest(req.Auth)
	if d == nil || d["username"] == "" {
		return
	}

	fields := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"method":   req.Method,
		"username": d["username"],
		"realm":    d["realm"],
		"nonce":    d["nonce"],
		"uri":      d["uri"],
		"response": d["response"],
		"hashcat":  sipHashcat(req.Method, d),
	}
	for _, k := range []string{"algorithm", "qop", "cnonce", "nc"} {
		if v := d[k]; v != "" {
			fields[k] = v
		}
	}
	for k, v := range map[string]string{
		"user_agent": req.Headers["user-agent"],
		"from":       req.Headers["from"],
		"to":         req.Headers["to"],
		"call_id":    req.Headers["call-id"],
	} {
		if v != "" {
			fields[k] = v
		}
	}

	c.RecordWriter.Record("credential", "sip", raddr.String(), fields)
}

// sipParseDigest parses a Digest credentials header value into a map of
// lowercase parameter names to unquoted values, returning nil for any other
// authentication scheme.
func sipParseDigest(value string) map[string]string {
	scheme, params, _ := strings.Cut(strings.TrimSpace(value), " ")
	if !strings.EqualFold(scheme, "Digest") {
		return nil
	}

	res := make(map[string]string)
	for _, p := range sipSplitParams(params) {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = strings.ReplaceAll(v[1:len(v)-1], "\\\"", "\"")
		}
		res[k] = v
	}
	return res
}

// sipSplitParams splits a comma-separated parameter list, leaving commas
// inside quoted values intact
func sipSplitParams(s string) []string {
	var parts []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && quoted:
			i++
		case s[i] == '"':
			quoted = !quoted
		case s[i] == ',' && !quoted:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// sipHashcat formats captured Digest credentials for hashcat mode 11400.
// The fields, in order and separated by asterisks, are:
//
//	$sip$*URI_server*URI_client*username*realm*method*URI_prefix*URI_resource*URI_suffix*nonce*cnonce*nc*qop*algorithm*response
//
// URI_server and URI_client are not part of the hash and are left empty.
// hashcat rebuilds the digest URI as prefix:resource, appending :suffix
// when the suffix is present, so the URI is split on its first two colons.
// cnonce, nc and qop are empty for RFC 2069 style responses that have no
// qop. The algorithm defaults to MD5 when the client did not send one.
func sipHashcat(method string, d map[string]string) string {
	prefix, resource, suffix := "", "", ""
	parts := strings.SplitN(d["uri"], ":", 3)
	prefix = parts[0]
	if len(parts) > 1 {
		resource = parts[1]
	}
	if len(parts) > 2 {
		suffix = parts[2]
	}

	algorithm := d["algorithm"]
	if algorithm == "" {
		algorithm = "MD5"
	}

	return strings.Join([]string{
		"$sip$",
		"", // URI_server
		"", // URI_client
		d["username"],
		d["realm"],
		method,
		prefix,
		resource,
		suffix,
		d["nonce"],
		d["cnonce"],
		d["nc"],
		d["qop"],
		algorithm,
		d["response"],
	}, "*")
}
