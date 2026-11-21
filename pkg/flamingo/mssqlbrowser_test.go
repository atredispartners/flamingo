package flamingo

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// mssqlBrowserTestConf returns a browser configured with fixed values and a
// channel that receives the query records it writes.
func mssqlBrowserTestConf(t *testing.T) (*ConfMSSQLBrowser, chan map[string]string) {
	t.Helper()
	rw := NewRecordWriter()
	got := make(chan map[string]string, 4)
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		got <- rec
		return nil
	})

	conf := NewConfMSSQLBrowser()
	conf.RecordWriter = rw
	return conf, got
}

func mssqlBrowserRecord(t *testing.T, got chan map[string]string) map[string]string {
	t.Helper()
	select {
	case rec := <-got:
		return rec
	case <-time.After(2 * time.Second):
		t.Fatal("no query recorded")
		return nil
	}
}

// TestMSSQLBrowserResponseFormat pins the SVR_RESP layout byte for byte: the
// 0x05 type, the little-endian length of the data that follows, and the
// semicolon-delimited instance list ending in an empty field.
func TestMSSQLBrowserResponseFormat(t *testing.T) {
	got := buildMSSQLBrowserResponse("SQL01", "MSSQLSERVER", "16.0.1000.6", 1433)

	body := "ServerName;SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;16.0.1000.6;tcp;1433;;"
	want := append([]byte{0x05, byte(len(body)), 0x00}, body...)
	if !bytes.Equal(got, want) {
		t.Fatalf("response mismatch\n got %q\nwant %q", got, want)
	}
	if n := int(binary.LittleEndian.Uint16(got[1:3])); n != len(got)-3 {
		t.Errorf("RESP_SIZE %d does not match the %d bytes of data", n, len(got)-3)
	}
}

// TestMSSQLBrowserAnswersWithConfiguredInstance checks the advertised instance
// points at the port the MSSQL listener is on and that the configured identity
// is what goes on the wire.
func TestMSSQLBrowserAnswersWithConfiguredInstance(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	conf.ServerName = "FILE02"
	conf.InstanceName = "SQLEXPRESS"
	conf.Version = "15.0.2000.5"
	conf.TargetPort = 11433

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 50000}
	resp := conf.handle([]byte{mssqlBrowserClntUcastEx}, src, 0, poisonTestDirectedDst(t))
	want := buildMSSQLBrowserResponse("FILE02", "SQLEXPRESS", "15.0.2000.5", 11433)
	if !bytes.Equal(resp, want) {
		t.Fatalf("response %q, want %q", resp, want)
	}

	rec := mssqlBrowserRecord(t, got)
	fields := map[string]string{
		"_type":               "query",
		"_proto":              "mssql-browser",
		"query":               "CLNT_UCAST_EX",
		"instance":            "",
		"answered":            "true",
		"advertised_instance": "SQLEXPRESS",
		"tcp_port":            "11433",
	}
	for k, v := range fields {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
}

// TestMSSQLBrowserEchoesRequestedInstance checks a lookup for a named instance
// is answered with that name, since a client that asked for host\instance
// ignores an answer for anything else.
func TestMSSQLBrowserEchoesRequestedInstance(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 50000}

	req := append([]byte{mssqlBrowserClntUcastInst}, "PAYROLL\x00"...)
	resp := conf.handle(req, src, 0, poisonTestDirectedDst(t))
	if !bytes.Contains(resp, []byte("InstanceName;PAYROLL;")) {
		t.Fatalf("response %q does not name the requested instance", resp)
	}
	if !bytes.Contains(resp, []byte("tcp;1433;;")) {
		t.Errorf("response %q does not point at the default MSSQL port", resp)
	}

	rec := mssqlBrowserRecord(t, got)
	if rec["instance"] != "PAYROLL" || rec["query"] != "CLNT_UCAST_INST" {
		t.Errorf("record instance %q query %q", rec["instance"], rec["query"])
	}
}

// TestMSSQLBrowserBroadcastGate pins the default split: a discovery request
// broadcast to the segment is observed and logged but not answered, and the
// same request is answered once broadcast answering is enabled.
func TestMSSQLBrowserBroadcastGate(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 50000}
	bcast := net.IPv4bcast
	req := []byte{mssqlBrowserClntBcastEx}

	if resp := conf.handle(req, src, 0, bcast); resp != nil {
		t.Errorf("answered a broadcast request by default: %q", resp)
	}
	rec := mssqlBrowserRecord(t, got)
	if rec["answered"] != "false" {
		t.Errorf("answered = %q, want false", rec["answered"])
	}
	if rec["reason"] != poisonBroadcastReason {
		t.Errorf("reason = %q, want %q", rec["reason"], poisonBroadcastReason)
	}
	if rec["query"] != "CLNT_BCAST_EX" {
		t.Errorf("the request must still be observed and logged: %v", rec)
	}

	// A platform that gives us no destination address is treated as broadcast.
	if resp := conf.handle(req, src, 0, nil); resp != nil {
		t.Errorf("answered a request with an unknown destination: %q", resp)
	}
	mssqlBrowserRecord(t, got)

	conf.AnswerBroadcast = true
	if resp := conf.handle(req, src, 0, bcast); resp == nil {
		t.Error("no answer to a broadcast request with AnswerBroadcast set")
	}
	if rec := mssqlBrowserRecord(t, got); rec["answered"] != "true" {
		t.Errorf("answered = %q, want true", rec["answered"])
	}
}

// TestMSSQLBrowserDirectedAnswered checks a request sent straight to this host
// is answered without AnswerBroadcast, like any other flamingo listener.
func TestMSSQLBrowserDirectedAnswered(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 50000}

	if resp := conf.handle([]byte{mssqlBrowserClntBcastEx}, src, 0, poisonTestDirectedDst(t)); resp == nil {
		t.Fatal("a directed request must be answered by default")
	}
	if rec := mssqlBrowserRecord(t, got); rec["answered"] != "true" {
		t.Errorf("answered = %q, want true", rec["answered"])
	}
}

// TestMSSQLBrowserMalformed checks that junk, oversized and hostile requests
// are dropped without an answer, a record, or a panic.
func TestMSSQLBrowserMalformed(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 50000}
	dst := poisonTestDirectedDst(t)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"unknown type", []byte{0x01}},
		{"server response echoed back", []byte{mssqlBrowserSvrResp, 0x00, 0x00}},
		{"instance name too long", append([]byte{mssqlBrowserClntUcastInst}, bytes.Repeat([]byte("A"), 40)...)},
		{"oversized datagram", append([]byte{mssqlBrowserClntBcastEx}, bytes.Repeat([]byte{0}, 4096)...)},
		{"semicolon injection", append([]byte{mssqlBrowserClntUcastInst}, ";tcp;4444;;\x00"...)},
		{"non-printable instance", append([]byte{mssqlBrowserClntUcastInst}, 0x01, 0x02, 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if resp := conf.handle(tc.data, src, 0, dst); resp != nil {
				t.Errorf("answered a malformed request with %q", resp)
			}
			select {
			case rec := <-got:
				t.Errorf("unexpected record %v", rec)
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestMSSQLBrowserConfigSanitized checks a configured value carrying the SSRP
// field delimiter cannot break the response layout.
func TestMSSQLBrowserConfigSanitized(t *testing.T) {
	conf, _ := mssqlBrowserTestConf(t)
	conf.ServerName = "SQL;01"
	conf.InstanceName = "A;B"

	resp, advertised := conf.answer("")
	if bytes.Count(resp[3:], []byte(";")) != 11 {
		t.Errorf("response %q has an unexpected number of fields", resp)
	}
	if advertised != "AB" {
		t.Errorf("advertised instance %q, want AB", advertised)
	}
	if !bytes.Contains(resp, []byte("ServerName;SQL01;InstanceName;AB;")) {
		t.Errorf("response %q is not the sanitized instance list", resp)
	}
}

// TestMSSQLBrowserEndToEnd drives the live socket and checks the unicast reply
// comes straight back to the querier.
func TestMSSQLBrowserEndToEnd(t *testing.T) {
	conf, got := mssqlBrowserTestConf(t)
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0 // OS picks a free port
	conf.TargetPort = 1433

	if err := SpawnMSSQLBrowser(conf); err != nil {
		t.Fatalf("SpawnMSSQLBrowser failed: %s", err)
	}
	defer conf.Shutdown()

	client, err := net.DialUDP("udp4", nil, conf.v4.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write([]byte{mssqlBrowserClntUcastEx}); err != nil {
		t.Fatalf("write failed: %s", err)
	}
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %s", err)
	}
	want := buildMSSQLBrowserResponse(MSSQLServerName, defaultMSSQLBrowserInstance, defaultMSSQLBrowserVersion, 1433)
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("end-to-end response %q, want %q", buf[:n], want)
	}
	if rec := mssqlBrowserRecord(t, got); rec["answered"] != "true" {
		t.Errorf("answered = %q, want true", rec["answered"])
	}
}

// TestMSSQLBrowserDefaults checks the constructor's defaults, which are what
// the command line relies on.
func TestMSSQLBrowserDefaults(t *testing.T) {
	conf := NewConfMSSQLBrowser()
	if conf.BindPort != 1434 {
		t.Errorf("BindPort = %d, want 1434", conf.BindPort)
	}
	if conf.TargetPort != 1433 {
		t.Errorf("TargetPort = %d, want the MSSQL listener port 1433", conf.TargetPort)
	}
	if conf.AnswerBroadcast {
		t.Error("AnswerBroadcast must default to off")
	}
	if conf.IsShutdown() {
		t.Error("a fresh configuration must not report shutdown")
	}
	conf.Shutdown()
	if !conf.IsShutdown() {
		t.Error("Shutdown did not take effect")
	}
	conf.Shutdown() // must stay safe to call twice
}
