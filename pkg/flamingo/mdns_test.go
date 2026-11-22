package flamingo

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// mdnsQueryWPAD is a real mDNS type-A query for "wpad.local".
var mdnsQueryWPAD = []byte{
	0x00, 0x00, // transaction id (mDNS uses 0)
	0x00, 0x00, // flags
	0x00, 0x01, // questions
	0x00, 0x00, // answer RRs
	0x00, 0x00, // authority RRs
	0x00, 0x00, // additional RRs
	0x04, 'w', 'p', 'a', 'd', // label "wpad"
	0x05, 'l', 'o', 'c', 'a', 'l', // label "local"
	0x00,       // end of name
	0x00, 0x01, // QTYPE A
	0x00, 0x01, // QCLASS IN
}

// mdnsWPADRawName is the encoded QNAME echoed back as the answer name.
var mdnsWPADRawName = []byte{0x04, 'w', 'p', 'a', 'd', 0x05, 'l', 'o', 'c', 'a', 'l'}

func TestParseMDNSQuery(t *testing.T) {
	name, rawName, qtype, wantV6, ok := parseMDNSQuery(mdnsQueryWPAD)
	if !ok {
		t.Fatalf("expected query to parse")
	}
	if name != "wpad.local" {
		t.Errorf("name = %q, want wpad.local", name)
	}
	if !bytes.Equal(rawName, mdnsWPADRawName) {
		t.Errorf("rawName = %s, want %s", hex.EncodeToString(rawName), hex.EncodeToString(mdnsWPADRawName))
	}
	if qtype != "A" || wantV6 {
		t.Errorf("qtype = %q wantV6 = %v, want A false", qtype, wantV6)
	}
}

func TestBuildMDNSAnswerA(t *testing.T) {
	got := buildMDNSAnswer(mdnsWPADRawName, false, net.ParseIP("1.2.3.4"), defaultMDNSTTL)

	want := []byte{
		0x00, 0x00, // transaction id
		0x84, 0x00, // flags QR=1 AA=1
		0x00, 0x00, // questions
		0x00, 0x01, // answer RRs
		0x00, 0x00, // authority RRs
		0x00, 0x00, // additional RRs
		0x04, 'w', 'p', 'a', 'd', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00, // answer name
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN (cache-flush bit off)
		0x00, 0x00, 0x00, 0x78, // TTL 120
		0x00, 0x04, // RDLENGTH
		0x01, 0x02, 0x03, 0x04, // address
	}
	if !bytes.Equal(got, want) {
		t.Errorf("mDNS A answer mismatch\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestMDNSEndToEnd(t *testing.T) {
	rw := NewRecordWriter()
	conf := NewConfMDNS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.SpoofIPv4 = "1.2.3.4"

	if err := SpawnMDNS(conf); err != nil {
		t.Fatalf("SpawnMDNS failed: %s", err)
	}
	defer conf.Shutdown()

	srvAddr := conf.v4.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp4", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write(mdnsQueryWPAD); err != nil {
		t.Fatalf("write failed: %s", err)
	}

	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %s", err)
	}

	want := buildMDNSAnswer(mdnsWPADRawName, false, net.ParseIP("1.2.3.4"), defaultMDNSTTL)
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("end-to-end answer mismatch\n got %s\nwant %s", hex.EncodeToString(buf[:n]), hex.EncodeToString(want))
	}
}

// TestParseMDNSQueryIgnoresKnownAnswers builds the query a real mDNS client
// sends when it is doing known-answer suppression (RFC 6762 section 7.1): one
// question followed by an answer record it already holds. The name and QTYPE
// must come from the question, not from a slice off the end of the datagram.
func TestParseMDNSQueryIgnoresKnownAnswers(t *testing.T) {
	question := []byte{
		4, 'w', 'p', 'a', 'd', 5, 'l', 'o', 'c', 'a', 'l', 0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
	knownAnswer := []byte{
		4, 'w', 'p', 'a', 'd', 5, 'l', 'o', 'c', 'a', 'l', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x78, // TTL
		0x00, 0x04, // RDLENGTH
		10, 0, 0, 5, // RDATA
	}
	data := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, // QDCOUNT 1
		0x00, 0x01, // ANCOUNT 1
		0x00, 0x00, 0x00, 0x00,
	}
	data = append(data, question...)
	data = append(data, knownAnswer...)

	name, rawName, qtype, wantV6, ok := parseMDNSQuery(data)
	if !ok {
		t.Fatal("a query with a known-answer record was rejected")
	}
	if name != "wpad.local" {
		t.Errorf("name = %q, want wpad.local", name)
	}
	if qtype != "A" || wantV6 {
		t.Errorf("qtype = %q wantV6 = %v, want A false", qtype, wantV6)
	}
	// The echoed owner name must be the question's labels alone. Slicing from
	// the end of the datagram used to swallow the known-answer record.
	want := question[:len(question)-5]
	if !bytes.Equal(rawName, want) {
		t.Errorf("rawName = % x, want % x", rawName, want)
	}
}

// TestParseMDNSQueryAcceptsUnicastResponseBit covers the QU bit mDNS packs
// into the top bit of QCLASS (RFC 6762 section 5.4).
func TestParseMDNSQueryAcceptsUnicastResponseBit(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		4, 'w', 'p', 'a', 'd', 5, 'l', 'o', 'c', 'a', 'l', 0x00,
		0x00, 0x01, // QTYPE A
		0x80, 0x01, // QCLASS IN with the QU bit set
	}
	name, _, qtype, _, ok := parseMDNSQuery(data)
	if !ok {
		t.Fatal("a QU query was rejected")
	}
	if name != "wpad.local" || qtype != "A" {
		t.Errorf("name = %q qtype = %q, want wpad.local A", name, qtype)
	}
}
