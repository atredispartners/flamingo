package flamingo

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// snmpTestEngineID is the authoritative engine ID used in the test messages.
var snmpTestEngineID = []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}

// snmpV3Options describes a test message.
type snmpV3Options struct {
	msgID      int64
	flags      byte
	engineID   []byte
	boots      int64
	etime      int64
	user       string
	authParams []byte
	privParams []byte
	reqID      int64
}

// snmpBuildV3 encodes an SNMPv3 USM message with a plaintext scoped GetRequest.
func snmpBuildV3(o snmpV3Options) []byte {
	usm := berTLV(berSequence, berCat(
		berTLV(berOctetString, o.engineID),
		berTLV(berInteger, berIntBytes(o.boots)),
		berTLV(berInteger, berIntBytes(o.etime)),
		berTLV(berOctetString, []byte(o.user)),
		berTLV(berOctetString, o.authParams),
		berTLV(berOctetString, o.privParams),
	))

	pdu := berTLV(0xa0, berCat( // GetRequest
		berTLV(berInteger, berIntBytes(o.reqID)),
		berTLV(berInteger, berIntBytes(0)),
		berTLV(berInteger, berIntBytes(0)),
		berTLV(berSequence, nil),
	))

	scoped := berTLV(berSequence, berCat(
		berTLV(berOctetString, o.engineID),
		berTLV(berOctetString, nil),
		pdu,
	))

	return berTLV(berSequence, berCat(
		berTLV(berInteger, berIntBytes(snmpVersion3)),
		berTLV(berSequence, berCat(
			berTLV(berInteger, berIntBytes(o.msgID)),
			berTLV(berInteger, berIntBytes(65507)),
			berTLV(berOctetString, []byte{o.flags}),
			berTLV(berInteger, berIntBytes(snmpSecurityUSM)),
		)),
		berTLV(berOctetString, usm),
		scoped,
	))
}

// snmpAuthedMessage builds an authenticated message whose digest is n bytes of
// a recognisable pattern.
func snmpAuthedMessage(user string, n int, boots int64) ([]byte, []byte) {
	digest := make([]byte, n)
	for i := range digest {
		digest[i] = byte(0xa0 + i)
	}
	return snmpBuildV3(snmpV3Options{
		msgID:      0x11223344,
		flags:      snmpFlagAuth | snmpFlagReportable,
		engineID:   snmpTestEngineID,
		boots:      boots,
		etime:      42,
		user:       user,
		authParams: digest,
		privParams: nil,
		reqID:      0x55667788,
	}), digest
}

// TestSNMPv3HashcatLine pins the exact $SNMPv3$ line a captured USM message
// produces: the auth type, the engine boots, the whole packet in hex with the
// authParameters zeroed in place, the engine ID, and the digest.
func TestSNMPv3HashcatLine(t *testing.T) {
	pkt, digest := snmpAuthedMessage("snmpuser", 12, 7)

	m, err := snmpParseV3(pkt)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if m.Username != "snmpuser" {
		t.Fatalf("username = %q", m.Username)
	}
	if m.EngineBoots != 7 {
		t.Fatalf("engine boots = %d, want 7", m.EngineBoots)
	}
	if !bytes.Equal(m.AuthParams, digest) {
		t.Fatalf("auth params = %x, want %x", m.AuthParams, digest)
	}

	// The zeroed packet must differ from the original in exactly the
	// authParameters content octets and nowhere else: every length and
	// every other field stays byte-identical.
	zeroed := m.snmpZeroedPacket(pkt)
	if len(zeroed) != len(pkt) {
		t.Fatalf("zeroed packet is %d bytes, original is %d", len(zeroed), len(pkt))
	}
	at := bytes.Index(pkt, digest)
	if at < 0 {
		t.Fatal("digest not found in the packet")
	}
	for i := range pkt {
		inRange := i >= at && i < at+len(digest)
		switch {
		case inRange && zeroed[i] != 0:
			t.Fatalf("byte %d inside authParameters is %#x, want 0", i, zeroed[i])
		case !inRange && zeroed[i] != pkt[i]:
			t.Fatalf("byte %d outside authParameters changed: %#x -> %#x", i, pkt[i], zeroed[i])
		}
	}

	line, mode := SNMPv3Hashcat(m, pkt)
	want := fmt.Sprintf("$SNMPv3$%d$%d$%s$%s$%s",
		snmpAuthTypeMD5, 7,
		hex.EncodeToString(zeroed),
		hex.EncodeToString(snmpTestEngineID),
		hex.EncodeToString(digest))
	if line != want {
		t.Errorf("hashcat line\n got %q\nwant %q", line, want)
	}
	if mode != 25000 {
		t.Errorf("mode = %d, want 25000", mode)
	}

	// Six fields, the first of which is the empty string before "$SNMPv3$".
	if parts := strings.Split(line, "$"); len(parts) != 7 {
		t.Errorf("line has %d $-separated parts, want 7: %q", len(parts), line)
	}
}

// TestSNMPv3AuthAlgorithms checks that each HMAC truncation length maps to the
// auth type and hashcat mode that go with it.
func TestSNMPv3AuthAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		n        int
		authType int
		mode     int
	}{
		{12, snmpAuthTypeMD5, 25000},
		{16, snmpAuthTypeSHA224, 26700},
		{24, snmpAuthTypeSHA256, 26800},
		{32, snmpAuthTypeSHA384, 26900},
		{48, snmpAuthTypeSHA512, 27300},
	} {
		pkt, _ := snmpAuthedMessage("u", tc.n, 1)
		m, err := snmpParseV3(pkt)
		if err != nil {
			t.Fatalf("%d-byte digest: parse: %s", tc.n, err)
		}
		line, mode := SNMPv3Hashcat(m, pkt)
		if mode != tc.mode {
			t.Errorf("%d-byte digest: mode = %d, want %d", tc.n, mode, tc.mode)
		}
		if prefix := fmt.Sprintf("$SNMPv3$%d$", tc.authType); !strings.HasPrefix(line, prefix) {
			t.Errorf("%d-byte digest: line %q does not start with %q", tc.n, line, prefix)
		}
	}

	// An unrecognised digest length yields no line rather than a wrong one.
	pkt, _ := snmpAuthedMessage("u", 20, 1)
	m, err := snmpParseV3(pkt)
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	if line, mode := SNMPv3Hashcat(m, pkt); line != "" || mode != 0 {
		t.Errorf("20-byte digest produced %q/%d, want no line", line, mode)
	}
}

// snmpTestServer spawns an SNMP collector on a free UDP port.
func snmpTestServer(t *testing.T) (string, chan map[string]string, *ConfSNMP) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 8)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfSNMP()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	if err := SpawnSNMP(conf); err != nil {
		t.Fatalf("SpawnSNMP: %s", err)
	}
	t.Cleanup(conf.Shutdown)
	return conf.listener.LocalAddr().String(), got, conf
}

// snmpSend writes one datagram and waits up to wait for a reply, returning nil
// when none arrives.
func snmpSend(t *testing.T, addr string, pkt []byte, wait time.Duration) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %s", err)
	}
	if wait <= 0 {
		return nil
	}
	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func snmpWaitRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("no record written")
		return nil
	}
}

// TestSNMPv3Capture runs an authenticated message through the listener and
// checks the recorded credential.
func TestSNMPv3Capture(t *testing.T) {
	addr, got, _ := snmpTestServer(t)
	pkt, digest := snmpAuthedMessage("netadmin", 12, 3)

	snmpSend(t, addr, pkt, time.Second)

	rec := snmpWaitRecord(t, got)
	if rec["_type"] != "credential" || rec["_proto"] != "snmp" {
		t.Fatalf("record = %v", rec)
	}
	if rec["username"] != "netadmin" {
		t.Errorf("username = %q, want netadmin", rec["username"])
	}
	if rec["version"] != "Version3" {
		t.Errorf("version = %q", rec["version"])
	}
	if rec["method"] != "usm" {
		t.Errorf("method = %q, want usm", rec["method"])
	}
	if rec["engine_boots"] != "3" {
		t.Errorf("engine_boots = %q, want 3", rec["engine_boots"])
	}
	if rec["engine_id"] != hex.EncodeToString(snmpTestEngineID) {
		t.Errorf("engine_id = %q", rec["engine_id"])
	}
	if !strings.HasSuffix(rec["hashcat"], "$"+hex.EncodeToString(digest)) {
		t.Errorf("hashcat line does not end with the digest: %q", rec["hashcat"])
	}
	if rec["hashcat_mode"] != "25000" {
		t.Errorf("hashcat_mode = %q, want 25000", rec["hashcat_mode"])
	}
}

// TestSNMPv3Discovery checks that an engine-discovery probe is answered with a
// Report naming this collector, which is what makes a real client come back
// authenticated.
func TestSNMPv3Discovery(t *testing.T) {
	addr, got, _ := snmpTestServer(t)

	probe := snmpBuildV3(snmpV3Options{
		msgID: 0x0badf00d,
		flags: snmpFlagReportable,
		boots: 0,
		etime: 0,
	})
	reply := snmpSend(t, addr, probe, time.Second)
	if reply == nil {
		t.Fatal("no Report in reply to a discovery probe")
	}

	m, err := snmpParseV3(reply)
	if err != nil {
		t.Fatalf("reply does not parse as SNMPv3: %s", err)
	}
	if m.MsgID != 0x0badf00d {
		t.Errorf("reply msgID = %#x, want the one we sent", m.MsgID)
	}
	if !bytes.Equal(m.EngineID, SNMPEngineID) {
		t.Errorf("reply engine id = %x, want %x", m.EngineID, SNMPEngineID)
	}
	if m.Flags&snmpFlagAuth != 0 {
		t.Error("the Report must not claim to be authenticated")
	}
	if !bytes.Contains(reply, snmpOIDUnknownEngineIDs) {
		t.Error("the Report does not carry usmStatsUnknownEngineIDs")
	}

	rec := snmpWaitRecord(t, got)
	if rec["_type"] != "access" || rec["method"] != "discovery" {
		t.Errorf("record = %v, want an access/discovery record", rec)
	}
}

// TestSNMPv3NoAuthUser checks that a noAuthNoPriv user name is still recorded,
// without a hash line it cannot have.
func TestSNMPv3NoAuthUser(t *testing.T) {
	addr, got, _ := snmpTestServer(t)

	pkt := snmpBuildV3(snmpV3Options{
		msgID:    1,
		flags:    snmpFlagReportable,
		engineID: snmpTestEngineID,
		boots:    1,
		user:     "public-v3",
	})
	snmpSend(t, addr, pkt, time.Second)

	rec := snmpWaitRecord(t, got)
	if rec["_type"] != "credential" || rec["username"] != "public-v3" {
		t.Fatalf("record = %v", rec)
	}
	if rec["method"] != "noauth" {
		t.Errorf("method = %q, want noauth", rec["method"])
	}
	if rec["hashcat"] != "" {
		t.Errorf("hashcat = %q, want empty for a noAuth user", rec["hashcat"])
	}
}

// TestSNMPv3Malformed feeds the parser truncated, oversized and nonsense input
// and requires that none of it panics or produces a credential.
func TestSNMPv3Malformed(t *testing.T) {
	good, _ := snmpAuthedMessage("u", 12, 1)

	cases := [][]byte{
		nil,
		{},
		{0x30},
		{0x30, 0x80},                         // indefinite length
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, // length past the end
		{0x30, 0x03, 0x02, 0x01, 0x03},       // version 3 and nothing else
		{0x1f, 0x01, 0x00},                   // high tag number
		append([]byte{0x30, 0x7f}, make([]byte, 4)...),
		bytes.Repeat([]byte{0x30, 0x02, 0x30, 0x00}, 64),
	}
	for i := 1; i < len(good); i++ {
		cases = append(cases, good[:i])
	}
	// An oversized username and digest must be refused, not stored.
	cases = append(cases, snmpBuildV3(snmpV3Options{
		msgID:      1,
		flags:      snmpFlagAuth,
		engineID:   snmpTestEngineID,
		boots:      1,
		user:       strings.Repeat("A", 512),
		authParams: make([]byte, 12),
	}))
	cases = append(cases, snmpBuildV3(snmpV3Options{
		msgID:      1,
		flags:      snmpFlagAuth,
		engineID:   snmpTestEngineID,
		boots:      1,
		user:       "u",
		authParams: make([]byte, 512),
	}))

	addr, got, _ := snmpTestServer(t)
	for _, pkt := range cases {
		// The parser must not panic.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("snmpParseV3 panicked on %x: %v", pkt, r)
				}
			}()
			snmpParseV3(pkt)
		}()
		snmpSend(t, addr, pkt, 0)
	}

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case rec := <-got:
			if rec["_type"] == "credential" {
				t.Fatalf("malformed input produced a credential: %v", rec)
			}
		case <-deadline:
			return
		}
	}
}

// TestSNMPv2cStillCaptured is the regression guard for the community-string
// path the v3 work sits next to.
func TestSNMPv2cStillCaptured(t *testing.T) {
	addr, got, _ := snmpTestServer(t)

	// A minimal v2c GetRequest carrying a community string.
	pkt := berTLV(berSequence, berCat(
		berTLV(berInteger, berIntBytes(1)), // version 1 == v2c
		berTLV(berOctetString, []byte("s3cr3t-community")),
		berTLV(0xa0, berCat(
			berTLV(berInteger, berIntBytes(0x1234)),
			berTLV(berInteger, berIntBytes(0)),
			berTLV(berInteger, berIntBytes(0)),
			berTLV(berSequence, berTLV(berSequence, berCat(
				berTLV(berOID, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}),
				berTLV(0x05, nil), // NULL
			))),
		)),
	))
	snmpSend(t, addr, pkt, time.Second)

	rec := snmpWaitRecord(t, got)
	if rec["_type"] != "credential" {
		t.Fatalf("record = %v", rec)
	}
	if rec["community"] != "s3cr3t-community" {
		t.Errorf("community = %q", rec["community"])
	}
}
