package flamingo

import (
	"net"
	"testing"
)

func mustPolicy(t *testing.T, respondTo, dontRespondTo, respondToName, dontRespondToName, dontRespondToTLD string, analyze bool) *ScopePolicy {
	t.Helper()
	p, err := NewScopePolicy(respondTo, dontRespondTo, respondToName, dontRespondToName, dontRespondToTLD, analyze)
	if err != nil {
		t.Fatalf("NewScopePolicy error: %s", err)
	}
	return p
}

func TestScopePolicyAnalyze(t *testing.T) {
	p := mustPolicy(t, "", "", "", "", "", true)
	ok, reason := p.ShouldRespond(net.ParseIP("10.0.0.5"), "wpad")
	if ok {
		t.Fatalf("analyze mode should never respond")
	}
	if reason != "analyze mode" {
		t.Errorf("reason = %q, want %q", reason, "analyze mode")
	}
}

func TestScopePolicyNilRespondsToAll(t *testing.T) {
	var p *ScopePolicy
	if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.5"), "anything"); !ok {
		t.Errorf("nil policy should respond to all")
	}
}

func TestScopePolicyRespondToIPAllowlist(t *testing.T) {
	p := mustPolicy(t, "10.0.0.0/24,192.168.1.10-20", "", "", "", "", false)

	cases := map[string]bool{
		"10.0.0.5":     true,  // in CIDR
		"10.0.1.5":     false, // outside CIDR
		"192.168.1.15": true,  // in last-octet range
		"192.168.1.25": false, // outside range
		"8.8.8.8":      false, // not listed at all
	}
	for ip, want := range cases {
		if ok, _ := p.ShouldRespond(net.ParseIP(ip), "host"); ok != want {
			t.Errorf("respondTo %s = %v, want %v", ip, ok, want)
		}
	}
}

func TestScopePolicyDontRespondToIP(t *testing.T) {
	p := mustPolicy(t, "", "10.0.0.5,172.16.0.0/16", "", "", "", false)

	cases := map[string]bool{
		"10.0.0.5":   false, // explicit deny
		"10.0.0.6":   true,  // not denied
		"172.16.9.9": false, // denied by CIDR
		"172.17.0.1": true,  // outside deny CIDR
	}
	for ip, want := range cases {
		if ok, _ := p.ShouldRespond(net.ParseIP(ip), "host"); ok != want {
			t.Errorf("dontRespondTo %s = %v, want %v", ip, ok, want)
		}
	}
}

func TestScopePolicyDenyBeatsAllow(t *testing.T) {
	// An address in both lists must be denied.
	p := mustPolicy(t, "10.0.0.0/24", "10.0.0.5", "", "", "", false)
	if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.5"), "host"); ok {
		t.Errorf("deny list must override allow list")
	}
	if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.6"), "host"); !ok {
		t.Errorf("allowed, non-denied address should respond")
	}
}

func TestScopePolicyRespondToName(t *testing.T) {
	p := mustPolicy(t, "", "", "WPAD,sqlint", "", "", false)

	cases := map[string]bool{
		"WPAD":     true,
		"wpad":     true, // case-insensitive
		"SQLINT":   true,
		"FILESERV": false, // not in allowlist
	}
	for name, want := range cases {
		if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.5"), name); ok != want {
			t.Errorf("respondToName %q = %v, want %v", name, ok, want)
		}
	}
}

func TestScopePolicyDontRespondToName(t *testing.T) {
	p := mustPolicy(t, "", "", "", "ISATAP,wpad", "", false)

	cases := map[string]bool{
		"ISATAP": false,
		"isatap": false, // case-insensitive
		"WPAD":   false,
		"DEV":    true,
	}
	for name, want := range cases {
		if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.5"), name); ok != want {
			t.Errorf("dontRespondToName %q = %v, want %v", name, ok, want)
		}
	}
}

func TestScopePolicyDontRespondToTLD(t *testing.T) {
	p := mustPolicy(t, "", "", "", "", "_dosvc,.local", false)

	cases := map[string]bool{
		"host._dosvc": false, // suffix match
		"foo.local":   false, // suffix match, case-insensitive
		"FOO.LOCAL":   false,
		"host.corp":   true,
		"dosvc.corp":  true, // _dosvc only as suffix
	}
	for name, want := range cases {
		if ok, _ := p.ShouldRespond(net.ParseIP("10.0.0.5"), name); ok != want {
			t.Errorf("dontRespondToTLD %q = %v, want %v", name, ok, want)
		}
	}
}

func TestParseIPMatcherErrors(t *testing.T) {
	bad := []string{"not-an-ip", "10.0.0.0/999", "10.0.0.1-", "-10.0.0.1"}
	for _, entry := range bad {
		if _, err := parseIPMatcher(entry); err == nil {
			t.Errorf("parseIPMatcher(%q) expected error", entry)
		}
	}
}

func TestClassifyDNSQuery(t *testing.T) {
	cases := []struct {
		tail   []byte
		qtype  string
		wantV6 bool
		ok     bool
	}{
		{[]byte{0x00, 0x01, 0x00, 0x01}, "A", false, true},
		{[]byte{0x00, 0xff, 0x00, 0x01}, "ANY", false, true},
		{[]byte{0x00, 0x1c, 0x00, 0x01}, "AAAA", true, true},
		{[]byte{0x00, 0x05, 0x00, 0x01}, "", false, false}, // CNAME, not answered
	}
	for _, c := range cases {
		data := append([]byte{0x00, 0x00, 0x00, 0x00}, c.tail...)
		qtype, wantV6, ok := classifyDNSQuery(data)
		if qtype != c.qtype || wantV6 != c.wantV6 || ok != c.ok {
			t.Errorf("classifyDNSQuery(%x) = (%q,%v,%v), want (%q,%v,%v)", c.tail, qtype, wantV6, ok, c.qtype, c.wantV6, c.ok)
		}
	}
}
