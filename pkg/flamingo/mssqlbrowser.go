package flamingo

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// SQL Server Resolution Protocol message types (MC-SQLR 2.2).
const (
	mssqlBrowserClntBcastEx   = 0x02 // enumerate every instance on the segment
	mssqlBrowserClntUcastEx   = 0x03 // enumerate every instance on one host
	mssqlBrowserClntUcastInst = 0x04 // look up one named instance
	mssqlBrowserSvrResp       = 0x05 // the server's instance list
)

// SQL Server Browser limits. An SSRP request is a type byte plus at most a
// 32-byte instance name and its terminator; anything longer is not a request
// this server answers.
const (
	mssqlBrowserMaxInstanceLen = 32
	mssqlBrowserMaxRequest     = 1 + mssqlBrowserMaxInstanceLen + 1
)

// Defaults for the instance the browser advertises. The version is SQL Server
// 2022 RTM, which is what the MSSQL listener's PRELOGIN response also claims.
const (
	defaultMSSQLBrowserInstance = "MSSQLSERVER"
	defaultMSSQLBrowserVersion  = "16.0.1000.6"
)

// ConfMSSQLBrowser holds the configuration for a SQL Server Browser (SSRP)
// responder.
//
// The browser is how clients find a SQL Server instance when they are given a
// host name without a port, or a `host\instance` pair. It answers with an
// instance list pointing at the port flamingo's own MSSQL listener is on, so a
// client that discovers us goes on to authenticate to us.
type ConfMSSQLBrowser struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter

	// ServerName is the machine name reported in the instance list.
	ServerName string
	// InstanceName is the instance reported for an enumeration request. A
	// request that names an instance is answered with the name it asked for,
	// so the client's own `host\instance` target resolves to us.
	InstanceName string
	// Version is the SQL Server version string reported in the instance list.
	Version string
	// TargetPort is the TCP port the advertised instance listens on. It should
	// be the port the MSSQL listener is bound to.
	TargetPort uint16

	// Policy scopes which broadcast discovery requests are answered, shared
	// with the name poisoners so one set of --poison-* flags governs every
	// broadcast answer flamingo gives. It is consulted only for broadcast
	// requests; directed ones are answered like any other listener's traffic.
	Policy *ScopePolicy

	// AnswerBroadcast enables answering broadcast queries, the active half of
	// instance discovery. Queries directed at this host are always answered.
	// Discovery requests are usually broadcast to the whole segment, so this
	// is what decides whether the browser only observes or also advertises.
	AnswerBroadcast bool

	shutdown bool
	v4       *ipv4.PacketConn
	v6       *ipv6.PacketConn
	m        sync.Mutex
}

// NewConfMSSQLBrowser creates a default configuration for the SQL Server
// Browser responder.
func NewConfMSSQLBrowser() *ConfMSSQLBrowser {
	return &ConfMSSQLBrowser{
		BindPort:     1434,
		BindHost:     "[::]",
		ServerName:   MSSQLServerName,
		InstanceName: defaultMSSQLBrowserInstance,
		Version:      defaultMSSQLBrowserVersion,
		TargetPort:   1433,
		Policy:       DefaultScopePolicy(),
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfMSSQLBrowser) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfMSSQLBrowser) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.v4 != nil {
		c.v4.Close()
	}
	if c.v6 != nil {
		c.v6.Close()
	}
}

// SpawnMSSQLBrowser starts a SQL Server Browser responder on the configured
// port. Every request is observed and recorded; whether one is answered
// follows the same split as the name poisoners, see handle.
func SpawnMSSQLBrowser(c *ConfMSSQLBrowser) error {
	v4host, v6host := poisonBindHosts(c.BindHost)

	var started bool
	if v4host != "" {
		v4, err := openPoisonV4(v4host, c.BindPort, nil, "mssql-browser")
		if err != nil {
			log.Debugf("mssql-browser: failed to open IPv4 socket on %s:%d: %s", v4host, c.BindPort, err)
		} else {
			c.v4 = v4
			started = true
			go poisonServeV4(v4, "mssql-browser", c.IsShutdown, c.handle)
		}
	}

	if v6host != "" {
		v6, err := openPoisonV6(v6host, c.BindPort, nil, "mssql-browser")
		if err != nil {
			log.Debugf("mssql-browser: failed to open IPv6 socket on %s:%d: %s", v6host, c.BindPort, err)
		} else {
			c.v6 = v6
			started = true
			go poisonServeV6(v6, "mssql-browser", c.IsShutdown, c.handle)
		}
	}

	if !started {
		return fmt.Errorf("failed to listen on %s:%d for mssql-browser", c.BindHost, c.BindPort)
	}

	log.Debugf("mssql-browser is listening on %s:%d", c.BindHost, c.BindPort)
	return nil
}

// parseMSSQLBrowserQuery decodes an SSRP request. It returns the request type,
// the instance name it asked for (empty for an enumeration), and whether this
// is a request the browser answers.
func parseMSSQLBrowserQuery(data []byte) (kind byte, instance string, ok bool) {
	if len(data) == 0 || len(data) > mssqlBrowserMaxRequest {
		return 0, "", false
	}
	switch data[0] {
	case mssqlBrowserClntBcastEx, mssqlBrowserClntUcastEx, mssqlBrowserClntUcastInst:
	default:
		return 0, "", false
	}
	// The enumeration requests are a single byte, but a client that appends an
	// instance name to one is asking about that instance either way.
	name := strings.TrimRight(string(data[1:]), "\x00")
	if !mssqlBrowserValidInstance(name) {
		return 0, "", false
	}
	return data[0], name, true
}

// mssqlBrowserValidInstance reports whether an instance name is one that can
// be echoed into a response. SSRP delimits its fields with semicolons and
// carries printable ASCII only, so anything else is refused rather than
// reflected into the answer.
func mssqlBrowserValidInstance(name string) bool {
	if len(name) > mssqlBrowserMaxInstanceLen {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r > 0x7e || r == ';' {
			return false
		}
	}
	return true
}

// mssqlBrowserQueryName names a request type for the record.
func mssqlBrowserQueryName(kind byte) string {
	switch kind {
	case mssqlBrowserClntBcastEx:
		return "CLNT_BCAST_EX"
	case mssqlBrowserClntUcastEx:
		return "CLNT_UCAST_EX"
	case mssqlBrowserClntUcastInst:
		return "CLNT_UCAST_INST"
	}
	return fmt.Sprintf("0x%02x", kind)
}

// buildMSSQLBrowserResponse builds an SVR_RESP message: the response type
// byte, the little-endian length of the data, and a semicolon-delimited
// instance list terminated by an empty field.
func buildMSSQLBrowserResponse(server, instance, version string, port uint16) []byte {
	body := fmt.Sprintf("ServerName;%s;InstanceName;%s;IsClustered;No;Version;%s;tcp;%d;;",
		server, instance, version, port)
	out := make([]byte, 0, 3+len(body))
	out = append(out, mssqlBrowserSvrResp)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

// answer builds the response for a request that asked for instance, which is
// empty for an enumeration request, and returns the instance name it
// advertised.
func (c *ConfMSSQLBrowser) answer(instance string) ([]byte, string) {
	server := mssqlBrowserField(cmp.Or(c.ServerName, MSSQLServerName))
	// A client that asked for a specific instance only accepts an answer
	// naming it, so the requested name is echoed back; an enumeration gets the
	// configured instance.
	name := mssqlBrowserField(cmp.Or(instance, c.InstanceName, defaultMSSQLBrowserInstance))
	version := mssqlBrowserField(cmp.Or(c.Version, defaultMSSQLBrowserVersion))
	return buildMSSQLBrowserResponse(server, name, version, c.targetPort()), name
}

// targetPort is the TCP port the advertised instance is claimed to listen on.
func (c *ConfMSSQLBrowser) targetPort() uint16 {
	if c.TargetPort == 0 {
		return 1433
	}
	return c.TargetPort
}

// mssqlBrowserField strips the SSRP field delimiter from a configured value so
// it cannot break the response layout.
func mssqlBrowserField(v string) string {
	return strings.ReplaceAll(v, ";", "")
}

// handle processes one SSRP datagram, records it, and returns any reply bytes.
//
// Instance discovery requests are usually broadcast to the whole segment.
// Answering one advertises a SQL Server that does not exist to every host that
// hears it, which is an active step onto the network, so it follows the same
// rule as the name poisoners: a request sent straight to this host is answered
// like any other flamingo listener would, a broadcast one only when
// AnswerBroadcast is set. Either way the request is observed and logged.
func (c *ConfMSSQLBrowser) handle(data []byte, src net.Addr, ifIndex int, dst net.IP) []byte {
	kind, instance, ok := parseMSSQLBrowserQuery(data)
	if !ok {
		log.Debugf("mssql-browser: ignoring malformed request from %s: % x", src, data)
		return nil
	}

	respond, reason := true, ""

	// Answering a broadcast discovery request advertises this host to a whole
	// segment, so it is gated and scoped exactly as the name poisoners are: an
	// operator who scopes a run with --poison-respond-to expects that to cover
	// every broadcast answer flamingo gives, not just the LLMNR ones. A query
	// directed at this host is answered like any other listener's traffic, so
	// only the broadcast case consults the policy.
	if !poisonIsDirected(dst) {
		switch {
		case !c.AnswerBroadcast:
			respond, reason = false, poisonBroadcastReason
		default:
			respond, reason = c.Policy.ShouldRespond(srcIP(src), instance)
		}
	}

	var resp []byte
	var advertised string
	if respond {
		resp, advertised = c.answer(instance)
	}
	c.record(src, kind, instance, advertised, respond, reason)
	return resp
}

func (c *ConfMSSQLBrowser) record(src net.Addr, kind byte, instance, advertised string, answered bool, reason string) {
	fields := map[string]string{
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		"query":    mssqlBrowserQueryName(kind),
		"instance": instance,
		"answered": fmt.Sprintf("%t", answered),
	}
	if answered {
		fields["advertised_instance"] = advertised
		fields["tcp_port"] = fmt.Sprintf("%d", c.targetPort())
	}
	if !answered && reason != "" {
		fields["reason"] = reason
	}
	c.RecordWriter.Record("query", "mssql-browser", src.String(), fields)
}
