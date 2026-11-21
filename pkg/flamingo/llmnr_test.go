package flamingo

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// llmnrQueryWPAD is a real single-label LLMNR type-A query for "wpad",
// transaction id 0x1337.
var llmnrQueryWPAD = []byte{
	0x13, 0x37, // transaction id
	0x00, 0x00, // flags (standard query)
	0x00, 0x01, // questions
	0x00, 0x00, // answer RRs
	0x00, 0x00, // authority RRs
	0x00, 0x00, // additional RRs
	0x04, 'w', 'p', 'a', 'd', 0x00, // QNAME
	0x00, 0x01, // QTYPE A
	0x00, 0x01, // QCLASS IN
}

func TestParseLLMNRQuery(t *testing.T) {
	tid, name, qtype, wantV6, ok := parseLLMNRQuery(llmnrQueryWPAD)
	if !ok {
		t.Fatalf("expected query to parse")
	}
	if !bytes.Equal(tid, []byte{0x13, 0x37}) {
		t.Errorf("tid = %x, want 1337", tid)
	}
	if string(name) != "wpad" {
		t.Errorf("name = %q, want wpad", name)
	}
	if qtype != "A" || wantV6 {
		t.Errorf("qtype = %q wantV6 = %v, want A false", qtype, wantV6)
	}

	// A query with non-zero flags (e.g. a response) must be rejected.
	resp := append([]byte(nil), llmnrQueryWPAD...)
	resp[2] = 0x80
	if _, _, _, _, ok := parseLLMNRQuery(resp); ok {
		t.Errorf("non-query flags should be rejected")
	}
}

func TestBuildLLMNRAnswerA(t *testing.T) {
	got := buildLLMNRAnswer([]byte{0x13, 0x37}, []byte("wpad"), []byte("wpad"), false, net.ParseIP("1.2.3.4"), defaultLLMNRTTL)

	want := []byte{
		0x13, 0x37, // transaction id
		0x80, 0x00, // flags QR=1
		0x00, 0x01, // questions
		0x00, 0x01, // answer RRs
		0x00, 0x00, // authority RRs
		0x00, 0x00, // additional RRs
		0x04, 'w', 'p', 'a', 'd', 0x00, // question name
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		0x04, 'w', 'p', 'a', 'd', 0x00, // answer name
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x1e, // TTL 30
		0x00, 0x04, // RDLENGTH
		0x01, 0x02, 0x03, 0x04, // address
	}
	if !bytes.Equal(got, want) {
		t.Errorf("LLMNR A answer mismatch\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestBuildLLMNRAnswerAAAA(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	got := buildLLMNRAnswer([]byte{0x13, 0x37}, []byte("wpad"), []byte("wpad"), true, ip, defaultLLMNRTTL)

	want := []byte{
		0x13, 0x37,
		0x80, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x04, 'w', 'p', 'a', 'd', 0x00,
		0x00, 0x1c, // QTYPE AAAA
		0x00, 0x01,
		0x04, 'w', 'p', 'a', 'd', 0x00,
		0x00, 0x1c, // TYPE AAAA
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x1e,
		0x00, 0x10, // RDLENGTH 16
	}
	want = append(want, ip.To16()...)
	if !bytes.Equal(got, want) {
		t.Errorf("LLMNR AAAA answer mismatch\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestLLMNRAnswerNameOverride(t *testing.T) {
	// handle() should echo the question name but answer with the override name.
	rw := NewRecordWriter()
	conf := NewConfLLMNR()
	conf.RecordWriter = rw
	conf.SpoofIPv4 = "1.2.3.4"
	conf.AnswerName = "evil"

	resp := conf.handle(llmnrQueryWPAD, &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5355}, 0)
	// Question name "wpad" is echoed, answer record name is "evil".
	if !bytes.Contains(resp, []byte{0x04, 'w', 'p', 'a', 'd'}) {
		t.Errorf("question name wpad not echoed: %s", hex.EncodeToString(resp))
	}
	if !bytes.Contains(resp, []byte{0x04, 'e', 'v', 'i', 'l'}) {
		t.Errorf("answer name override evil not present: %s", hex.EncodeToString(resp))
	}
}

func TestLLMNRNoSpoofNoAnswer(t *testing.T) {
	// With no override and an undeterminable interface, answer nothing.
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfLLMNR()
	conf.RecordWriter = rw
	// ifIndex 0 => no interface address; no SpoofIPv4 set.
	resp := conf.handle(llmnrQueryWPAD, &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5355}, 0)
	if resp != nil {
		t.Errorf("expected no answer when no spoof address available, got %s", hex.EncodeToString(resp))
	}

	// But the query must still be recorded (observed) with answered=false.
	select {
	case rec := <-got:
		if rec["answered"] != "false" {
			t.Errorf("answered = %q, want false", rec["answered"])
		}
		if rec["reason"] == "" {
			t.Errorf("expected a reason on an unanswered query")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected an observed-query record")
	}
}

func TestLLMNRAnalyzeModeRecordsButDoesNotAnswer(t *testing.T) {
	rw := NewRecordWriter()
	got := make(chan map[string]string, 1)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfLLMNR()
	conf.RecordWriter = rw
	conf.SpoofIPv4 = "1.2.3.4" // even with a spoof address, analyze answers nothing
	conf.Policy = mustPolicy(t, "", "", "", "", "", true)

	if resp := conf.handle(llmnrQueryWPAD, &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 5355}, 0); resp != nil {
		t.Errorf("analyze mode must not answer")
	}
	select {
	case rec := <-got:
		if rec["answered"] != "false" || rec["_proto"] != "llmnr" || rec["name"] != "wpad" {
			t.Errorf("unexpected record: %v", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected an observed-query record in analyze mode")
	}
}

// TestLLMNREndToEnd drives the live socket with a real query and verifies the
// unicast answer comes straight back to the querier's source address.
func TestLLMNREndToEnd(t *testing.T) {
	rw := NewRecordWriter()
	conf := NewConfLLMNR()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0 // OS picks a free port
	conf.RecordWriter = rw
	conf.SpoofIPv4 = "1.2.3.4"

	if err := SpawnLLMNR(conf); err != nil {
		t.Fatalf("SpawnLLMNR failed: %s", err)
	}
	defer conf.Shutdown()

	srvAddr := conf.v4.LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp4", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write(llmnrQueryWPAD); err != nil {
		t.Fatalf("write failed: %s", err)
	}

	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %s", err)
	}

	want := buildLLMNRAnswer([]byte{0x13, 0x37}, []byte("wpad"), []byte("wpad"), false, net.ParseIP("1.2.3.4"), defaultLLMNRTTL)
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("end-to-end answer mismatch\n got %s\nwant %s", hex.EncodeToString(buf[:n]), hex.EncodeToString(want))
	}
}
