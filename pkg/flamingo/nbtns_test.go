package flamingo

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// encodeNetBIOSName performs the RFC1001 first-level encoding a real NBT-NS
// client uses: the 16-byte name (15 chars space-padded + 1 suffix byte) becomes
// 32 nibble-encoded bytes.
func encodeNetBIOSName(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := 0; i < 15; i++ {
		if i < len(name) {
			raw[i] = name[i]
		} else {
			raw[i] = ' '
		}
	}
	raw[15] = suffix

	enc := make([]byte, 0, 32)
	for _, b := range raw {
		enc = append(enc, 0x41+(b>>4), 0x41+(b&0x0f))
	}
	return enc
}

// nbtnsQuery builds a full NBT-NS name query datagram for the given name/suffix.
func nbtnsQuery(tid []byte, name string, suffix byte) []byte {
	out := make([]byte, 0, 50)
	out = append(out, tid...)     // transaction id
	out = append(out, 0x01, 0x10) // flags: name query, RD, broadcast
	out = append(out, 0x00, 0x01) // questions
	out = append(out, 0x00, 0x00) // answer RRs
	out = append(out, 0x00, 0x00) // authority RRs
	out = append(out, 0x00, 0x00) // additional RRs
	out = append(out, 0x20)       // encoded name length (32)
	out = append(out, encodeNetBIOSName(name, suffix)...)
	out = append(out, 0x00)       // name terminator
	out = append(out, 0x00, 0x20) // QTYPE NB
	out = append(out, 0x00, 0x01) // QCLASS IN
	return out
}

func TestDecodeNetBIOSName(t *testing.T) {
	enc := encodeNetBIOSName("WPAD", 0x00)
	name, suffix := decodeNetBIOSName(enc)
	if name != "WPAD" {
		t.Errorf("name = %q, want WPAD", name)
	}
	if suffix != 0x00 {
		t.Errorf("suffix = 0x%02x, want 0x00", suffix)
	}

	// A domain-controller suffix (0x1c) should decode too.
	enc = encodeNetBIOSName("CORP", 0x1c)
	name, suffix = decodeNetBIOSName(enc)
	if name != "CORP" || suffix != 0x1c {
		t.Errorf("got (%q,0x%02x), want (CORP,0x1c)", name, suffix)
	}
}

func TestParseNBTNSQuery(t *testing.T) {
	q := nbtnsQuery([]byte{0x12, 0x34}, "WPAD", 0x00)
	name, suffix, ok := parseNBTNSQuery(q)
	if !ok {
		t.Fatalf("expected query to parse")
	}
	if name != "WPAD" || suffix != 0x00 {
		t.Errorf("got (%q,0x%02x), want (WPAD,0x00)", name, suffix)
	}

	// A response (wrong flags) must be rejected.
	resp := append([]byte(nil), q...)
	resp[2], resp[3] = 0x85, 0x00
	if _, _, ok := parseNBTNSQuery(resp); ok {
		t.Errorf("non-query flags should be rejected")
	}
}

func TestBuildNBTNSAnswer(t *testing.T) {
	q := nbtnsQuery([]byte{0x12, 0x34}, "WPAD", 0x00)
	got := buildNBTNSAnswer(q, net.ParseIP("1.2.3.4"), defaultNBTNSTTL)

	want := make([]byte, 0, 62)
	want = append(want, 0x12, 0x34)             // transaction id
	want = append(want, 0x85, 0x00)             // flags
	want = append(want, 0x00, 0x00)             // questions
	want = append(want, 0x00, 0x01)             // answer RRs
	want = append(want, 0x00, 0x00)             // authority RRs
	want = append(want, 0x00, 0x00)             // additional RRs
	want = append(want, q[12:46]...)            // echoed encoded name (34 bytes)
	want = append(want, 0x00, 0x20)             // TYPE NB
	want = append(want, 0x00, 0x01)             // CLASS IN
	want = append(want, 0x00, 0x04, 0x93, 0xe0) // TTL 300000
	want = append(want, 0x00, 0x06)             // RDLENGTH
	want = append(want, 0x00, 0x00)             // NB flags: B-node, unique
	want = append(want, 0x01, 0x02, 0x03, 0x04) // address

	if !bytes.Equal(got, want) {
		t.Errorf("NBT-NS answer mismatch\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestNBTNSEndToEnd(t *testing.T) {
	rw := NewRecordWriter()
	conf := NewConfNBTNS()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw
	conf.SpoofIPv4 = "1.2.3.4"

	if err := SpawnNBTNS(conf); err != nil {
		t.Fatalf("SpawnNBTNS failed: %s", err)
	}
	defer conf.Shutdown()

	srvAddr := conf.v4.LocalAddr().(*net.UDPAddr)
	client, err := net.DialUDP("udp4", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	q := nbtnsQuery([]byte{0x12, 0x34}, "WPAD", 0x00)
	if _, err := client.Write(q); err != nil {
		t.Fatalf("write failed: %s", err)
	}

	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %s", err)
	}

	want := buildNBTNSAnswer(q, net.ParseIP("1.2.3.4"), defaultNBTNSTTL)
	if !bytes.Equal(buf[:n], want) {
		t.Errorf("end-to-end answer mismatch\n got %s\nwant %s", hex.EncodeToString(buf[:n]), hex.EncodeToString(want))
	}
}
