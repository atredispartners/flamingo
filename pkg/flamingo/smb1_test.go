package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// smb1TestHeader builds an SMB1 request header for command.
func smb1TestHeader(command byte, unicode bool, uid uint16) []byte {
	pkt := make([]byte, 32)
	copy(pkt, smb1Magic)
	pkt[4] = command
	pkt[9] = smb1FlagsCaseInsensitive
	flags2 := uint16(smb1Flags2LongNames | smb1Flags2NTStatus)
	if unicode {
		flags2 |= smb1Flags2Unicode
	}
	binary.LittleEndian.PutUint16(pkt[10:12], flags2)
	binary.LittleEndian.PutUint16(pkt[28:30], uid)
	binary.LittleEndian.PutUint16(pkt[30:32], 1) // MID
	return pkt
}

// smb1TestMessage assembles an SMB1 message from a header, parameter words
// and a byte block.
func smb1TestMessage(hdr, words, data []byte) []byte {
	pkt := append(append([]byte(nil), hdr...), byte(len(words)/2))
	pkt = append(pkt, words...)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)))
	return append(pkt, data...)
}

// smb1TestNegotiateRequest builds an SMB1 NEGOTIATE offering the given
// dialect strings.
func smb1TestNegotiateRequest(unicode bool, dialects ...string) []byte {
	var data []byte
	for _, d := range dialects {
		data = append(data, 0x02)
		data = append(data, d...)
		data = append(data, 0)
	}
	return smb1TestMessage(smb1TestHeader(smb1CommandNegotiate, unicode, 0), nil, data)
}

// smb1TestSetupLegacy builds a word count 13 SESSION_SETUP_ANDX, the NT LM
// 0.12 form that carries the LM and NT responses directly.
func smb1TestSetupLegacy(unicode bool, lm, nt []byte, account, domain, nativeOS, nativeLM string) []byte {
	words := make([]byte, 26)
	words[0] = smb1AndXNone
	binary.LittleEndian.PutUint16(words[4:6], 4356)
	binary.LittleEndian.PutUint16(words[6:8], 50)
	binary.LittleEndian.PutUint16(words[14:16], uint16(len(lm)))
	binary.LittleEndian.PutUint16(words[16:18], uint16(len(nt)))

	data := append(append([]byte(nil), lm...), nt...)
	// The byte block of a word count 13 message starts at packet offset 61,
	// so a UTF-16 string after an even-length response needs a pad byte.
	if unicode && (61+len(data))%2 != 0 {
		data = append(data, 0)
	}
	for _, s := range []string{account, domain, nativeOS, nativeLM} {
		data = append(data, smb1String(s, unicode)...)
	}
	return smb1TestMessage(smb1TestHeader(smb1CommandSessionSetupAndX, unicode, 0), words, data)
}

// smb1TestSetupExtended builds a word count 12 SESSION_SETUP_ANDX carrying an
// extended security blob.
func smb1TestSetupExtended(unicode bool, uid uint16, blob []byte) []byte {
	words := make([]byte, 24)
	words[0] = smb1AndXNone
	binary.LittleEndian.PutUint16(words[4:6], 4356)
	binary.LittleEndian.PutUint16(words[6:8], 50)
	binary.LittleEndian.PutUint16(words[14:16], uint16(len(blob)))

	data := append([]byte(nil), blob...)
	if unicode && (59+len(data))%2 != 0 {
		data = append(data, 0)
	}
	data = append(data, smb1String("Windows 2000 2195", unicode)...)
	data = append(data, smb1String("Windows 2000 5.0", unicode)...)

	hdr := smb1TestHeader(smb1CommandSessionSetupAndX, unicode, uid)
	binary.LittleEndian.PutUint16(hdr[10:12],
		binary.LittleEndian.Uint16(hdr[10:12])|smb1Flags2ExtendedSecurity)
	return smb1TestMessage(hdr, words, data)
}

// smb1TestBytes returns the word block and byte block of an SMB1 message.
func smb1TestBytes(t *testing.T, pkt []byte) (words, data []byte) {
	t.Helper()
	if !smb1IsHeader(pkt) {
		t.Fatalf("not an SMB1 message: %x", pkt)
	}
	wc := int(pkt[32])
	if len(pkt) < 35+wc*2 {
		t.Fatalf("SMB1 message truncated: %x", pkt)
	}
	words = pkt[33 : 33+wc*2]
	bc := int(binary.LittleEndian.Uint16(pkt[33+wc*2:]))
	data = pkt[35+wc*2:]
	if bc < len(data) {
		data = data[:bc]
	}
	return words, data
}

func smb1TestStatus(pkt []byte) uint32 {
	return binary.LittleEndian.Uint32(pkt[5:9])
}

// TestSMB1NegotiateUpgrade checks that a client offering SMB2 in its SMB1
// multi-protocol NEGOTIATE is answered with the SMB2 wildcard dialect, and
// that the SMB2 negotiation that follows works.
func TestSMB1NegotiateUpgrade(t *testing.T) {
	for _, offered := range []string{"SMB 2.002", "SMB 2.???"} {
		t.Run(offered, func(t *testing.T) {
			addr, _, _ := smbTestServer(t)
			conn := smbTestDial(t, addr)

			smbTestSend(t, conn, nbtSessionMessage,
				smb1TestNegotiateRequest(true, "NT LM 0.12", offered))
			_, pkt := smbTestRecv(t, conn)

			p := wire.PacketCodec(pkt)
			if p.IsInvalidResponse() || p.Command() != wire.SMB2_NEGOTIATE {
				t.Fatalf("SMB1 NEGOTIATE was not answered with an SMB2 NEGOTIATE response: %x", pkt)
			}
			res := wire.NegotiateResponseDecoder(p.Body())
			if res.IsInvalid() {
				t.Fatalf("invalid NEGOTIATE response: %x", pkt)
			}
			if res.DialectRevision() != smb1WildcardDialect {
				t.Fatalf("dialect = 0x%04x, want the wildcard 0x02ff", res.DialectRevision())
			}

			// The client now starts again in SMB2.
			if got := smbTestNegotiate(t, conn, []wire.Dialect{wire.SMB311}).DialectRevision(); got != wire.SMB311 {
				t.Fatalf("second negotiation chose 0x%04x, want 0x0311", got)
			}
		})
	}
}

// TestSMB1NegotiateNTLM checks the SMB1-only path: NT LM 0.12 is selected and
// the response carries flamingo's fixed challenge, with signing optional and
// extended security not advertised.
func TestSMB1NegotiateNTLM(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestNegotiateRequest(false, "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"))
	_, pkt := smbTestRecv(t, conn)

	if !smb1IsHeader(pkt) || pkt[4] != smb1CommandNegotiate {
		t.Fatalf("not an SMB1 NEGOTIATE response: %x", pkt)
	}
	if pkt[9]&smb1FlagsReply == 0 {
		t.Error("reply flag not set on the response")
	}
	words, data := smb1TestBytes(t, pkt)
	if len(words) != 34 {
		t.Fatalf("word count = %d words, want 17", len(words)/2)
	}
	if idx := binary.LittleEndian.Uint16(words[0:2]); idx != 2 {
		t.Fatalf("dialect index = %d, want 2 (NT LM 0.12)", idx)
	}
	if words[2]&0x02 == 0 {
		t.Error("challenge/response passwords not advertised")
	}
	if caps := binary.LittleEndian.Uint32(words[19:23]); caps&0x80000000 != 0 {
		t.Error("CAP_EXTENDED_SECURITY advertised; the fixed challenge would then be unreachable")
	}
	if words[33] != 8 {
		t.Fatalf("challenge length = %d, want 8", words[33])
	}
	if !bytes.HasPrefix(data, NTLMConf.Challenge[:]) {
		t.Fatalf("challenge = %x, want %x", data, NTLMConf.Challenge[:])
	}
}

// TestSMB1NegotiateNoNTDialect checks that a client offering only pre-NT
// dialects is told no dialect was selected rather than being answered with a
// response it cannot parse.
func TestSMB1NegotiateNoNTDialect(t *testing.T) {
	addr, _, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestNegotiateRequest(false, "PC NETWORK PROGRAM 1.0", "LANMAN1.0"))
	_, pkt := smbTestRecv(t, conn)

	words, _ := smb1TestBytes(t, pkt)
	if len(words) != 2 {
		t.Fatalf("word count = %d words, want 1", len(words)/2)
	}
	if idx := binary.LittleEndian.Uint16(words); idx != smb1NoDialect {
		t.Fatalf("dialect index = 0x%04x, want 0xffff", idx)
	}
}

// TestSMB1SessionSetupLegacyNTLMv2 captures the non-extended form, which puts
// the responses in the LM and NT fields and the identity in plaintext.
func TestSMB1SessionSetupLegacyNTLMv2(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionMessage, smb1TestNegotiateRequest(true, "NT LM 0.12"))
	smbTestRecv(t, conn)

	// The client blob is built against the AV_PAIR block of our CHALLENGE
	// identity, exactly as a client would after an extended-security
	// exchange; in SMB1 it simply travels in the NT field instead.
	info := smbTestTargetInfo(t, NTLMChallengeMessage(0))
	blob := ntlmTestV2Blob(info, false)
	proof := ntlmTestV2Proof("Password1", "dave", "CORP", NTLMConf.Challenge[:], blob)
	nt := append(append([]byte(nil), proof...), blob...)
	lm := make([]byte, 24)

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestSetupLegacy(true, lm, nt, "dave", "CORP", "Windows 7 7601", "Windows 7 6.1"))
	_, pkt := smbTestRecv(t, conn)
	if smb1TestStatus(pkt) != smbStatusLogonFailure {
		t.Fatalf("status 0x%08x, want STATUS_LOGON_FAILURE", smb1TestStatus(pkt))
	}

	rec := smbTestWaitCred(t, got)
	want := map[string]string{
		"username":       "dave",
		"domain":         "CORP",
		"ntlm_version":   "v2",
		"hashcat_mode":   "5600",
		"dialect":        "NT LM 0.12",
		"client_version": "Windows 7 7601",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
	wantLine := fmt.Sprintf("dave::CORP:%s:%s:%s", hex.EncodeToString(NTLMConf.Challenge[:]),
		hex.EncodeToString(proof), hex.EncodeToString(blob))
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
}

// TestSMB1SessionSetupLegacyNTLMv1 is the case this code path exists for: an
// old client answering the fixed challenge with LM and NTLMv1 responses.
func TestSMB1SessionSetupLegacyNTLMv1(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionMessage, smb1TestNegotiateRequest(false, "NT LM 0.12"))
	smbTestRecv(t, conn)

	nt := ntlmTestV1Response("Password1", NTLMConf.Challenge[:])
	lm := ntlmTestDESL([]byte("LMHASHLMHASHLMHASH00"), NTLMConf.Challenge[:])

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestSetupLegacy(false, lm, nt, "eve", "WORKGROUP", "Windows 2000 2195", "Windows 2000 5.0"))
	_, pkt := smbTestRecv(t, conn)
	if smb1TestStatus(pkt) != smbStatusLogonFailure {
		t.Fatalf("status 0x%08x, want STATUS_LOGON_FAILURE", smb1TestStatus(pkt))
	}

	rec := smbTestWaitCred(t, got)
	if rec["username"] != "eve" || rec["domain"] != "WORKGROUP" {
		t.Errorf("identity = %q/%q, want eve/WORKGROUP", rec["username"], rec["domain"])
	}
	if rec["ntlm_version"] != "v1" || rec["hashcat_mode"] != "5500" {
		t.Fatalf("ntlm_version=%q hashcat_mode=%q, want v1/5500", rec["ntlm_version"], rec["hashcat_mode"])
	}
	// SMB1 carries no workstation of its own; mode 5500 takes it from the
	// NetBIOS calling name, which this connection never sent.
	wantLine := fmt.Sprintf("eve:::%s:%s:%s", hex.EncodeToString(lm),
		hex.EncodeToString(nt), hex.EncodeToString(NTLMConf.Challenge[:]))
	if rec["hashcat"] != wantLine {
		t.Errorf("hashcat = %q, want %q", rec["hashcat"], wantLine)
	}
}

// TestSMB1SessionSetupExtended drives the NTLMSSP exchange carried in an SMB1
// security blob, which takes two SESSION_SETUP_ANDX round trips.
func TestSMB1SessionSetupExtended(t *testing.T) {
	addr, got, _ := smbTestServer(t)
	conn := smbTestDial(t, addr)

	smbTestSend(t, conn, nbtSessionMessage, smb1TestNegotiateRequest(true, "NT LM 0.12"))
	smbTestRecv(t, conn)

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestSetupExtended(true, 0, smbSPNEGONegTokenResp(smbTestNegotiateToken())))
	_, pkt := smbTestRecv(t, conn)
	if smb1TestStatus(pkt) != smbStatusMoreProcessingRequired {
		t.Fatalf("status 0x%08x, want STATUS_MORE_PROCESSING_REQUIRED", smb1TestStatus(pkt))
	}
	uid := binary.LittleEndian.Uint16(pkt[28:30])
	if uid == 0 {
		t.Error("no UID handed out for the second round trip")
	}
	words, data := smb1TestBytes(t, pkt)
	if len(words) != 8 {
		t.Fatalf("word count = %d words, want 4", len(words)/2)
	}
	blobLen := int(binary.LittleEndian.Uint16(words[6:8]))
	if blobLen == 0 || blobLen > len(data) {
		t.Fatalf("security blob length = %d, byte block = %d", blobLen, len(data))
	}
	challenge := FindNTLMSSP(data[:blobLen])
	if NTLMMessageType(challenge) != NTLMTypeChallenge {
		t.Fatalf("security blob does not carry a CHALLENGE: %x", data[:blobLen])
	}

	blob := ntlmTestV2Blob(smbTestTargetInfo(t, challenge), false)
	proof := ntlmTestV2Proof("Password1", "frank", "CORP", NTLMConf.Challenge[:], blob)
	auth := ntlmTestAuthMsg("frank", "CORP", "LEGACY01", nil,
		append(append([]byte(nil), proof...), blob...), nil, 0)

	smbTestSend(t, conn, nbtSessionMessage,
		smb1TestSetupExtended(true, uid, smbSPNEGONegTokenResp(auth)))
	_, pkt = smbTestRecv(t, conn)
	if smb1TestStatus(pkt) != smbStatusLogonFailure {
		t.Fatalf("status 0x%08x, want STATUS_LOGON_FAILURE", smb1TestStatus(pkt))
	}

	rec := smbTestWaitCred(t, got)
	want := map[string]string{
		"username":     "frank",
		"domain":       "CORP",
		"workstation":  "LEGACY01",
		"ntlm_version": "v2",
		"hashcat_mode": "5600",
		"dialect":      "NT LM 0.12",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %q, want %q", k, rec[k], v)
		}
	}
}

func TestSMB1ParseNegotiate(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
		want []string
		err  bool
	}{
		{
			name: "windows dialect list",
			pkt:  smb1TestNegotiateRequest(true, "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12", "SMB 2.002", "SMB 2.???"),
			want: []string{"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12", "SMB 2.002", "SMB 2.???"},
		},
		{
			name: "unterminated final dialect",
			pkt: func() []byte {
				pkt := smb1TestNegotiateRequest(false, "NT LM 0.12")
				return pkt[:len(pkt)-1]
			}(),
			want: []string{"NT LM 0.12"},
		},
		{"no dialects", smb1TestNegotiateRequest(false), nil, true},
		{"truncated header", smb1TestNegotiateRequest(false, "NT LM 0.12")[:34], nil, true},
		{"word count not zero", smb1TestMessage(smb1TestHeader(smb1CommandNegotiate, false, 0), []byte{0, 0}, []byte{0x02, 'A', 0}), nil, true},
		{
			name: "byte count longer than the message",
			pkt: func() []byte {
				pkt := smb1TestNegotiateRequest(false, "NT LM 0.12")
				binary.LittleEndian.PutUint16(pkt[33:35], 0xffff)
				return pkt
			}(),
			want: []string{"NT LM 0.12"},
		},
		{
			name: "bad buffer format byte",
			pkt:  smb1TestMessage(smb1TestHeader(smb1CommandNegotiate, false, 0), nil, []byte{0x04, 'A', 0}),
			err:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := smb1ParseNegotiate(tc.pkt)
			if tc.err {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("dialects = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("dialects = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestSMB1DialectSelection(t *testing.T) {
	full := []string{"PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12", "SMB 2.???"}
	if !smb1OffersSMB2(full) {
		t.Error("SMB 2.??? not recognised as an SMB2 offer")
	}
	if smb1OffersSMB2([]string{"NT LM 0.12"}) {
		t.Error("NT LM 0.12 mistaken for an SMB2 offer")
	}
	if got := smb1DialectIndex(full, smb1NTLMDialect); got != 2 {
		t.Errorf("NT LM 0.12 index = %d, want 2", got)
	}
	if got := smb1DialectIndex([]string{"LANMAN1.0"}, smb1NTLMDialect); got != -1 {
		t.Errorf("missing dialect index = %d, want -1", got)
	}
}

// TestSMB1ParseSessionSetupForms covers the three word counts the parser
// accepts and the UTF-16 alignment rule that separates the responses from the
// identity strings.
func TestSMB1ParseSessionSetupForms(t *testing.T) {
	lm := bytes.Repeat([]byte{0xaa}, 24)
	nt := bytes.Repeat([]byte{0xbb}, 24)

	t.Run("word count 13 unicode", func(t *testing.T) {
		ss, err := smb1ParseSessionSetup(smb1TestSetupLegacy(true, lm, nt, "alice", "CORP", "Windows", "LanMan"))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !bytes.Equal(ss.LM, lm) || !bytes.Equal(ss.NT, nt) {
			t.Fatalf("responses = %x/%x", ss.LM, ss.NT)
		}
		if ss.Account != "alice" || ss.Domain != "CORP" {
			t.Fatalf("identity = %q/%q, want alice/CORP", ss.Account, ss.Domain)
		}
		if ss.NativeOS != "Windows" || ss.NativeLM != "LanMan" {
			t.Fatalf("native strings = %q/%q", ss.NativeOS, ss.NativeLM)
		}
	})

	t.Run("word count 13 oem", func(t *testing.T) {
		ss, err := smb1ParseSessionSetup(smb1TestSetupLegacy(false, lm, nt, "bob", "WORKGROUP", "OS/2", "LM2.1"))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if ss.Account != "bob" || ss.Domain != "WORKGROUP" || ss.NativeOS != "OS/2" {
			t.Fatalf("identity = %q/%q/%q", ss.Account, ss.Domain, ss.NativeOS)
		}
	})

	t.Run("word count 12", func(t *testing.T) {
		blob := smbSPNEGONegTokenResp(smbTestNegotiateToken())
		ss, err := smb1ParseSessionSetup(smb1TestSetupExtended(true, 0, blob))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !bytes.Equal(ss.Blob, blob) {
			t.Fatalf("security blob = %x, want %x", ss.Blob, blob)
		}
		if ss.Account != "" || ss.Domain != "" {
			t.Errorf("extended security carries no plaintext identity, got %q/%q", ss.Account, ss.Domain)
		}
		if ss.NativeOS != "Windows 2000 2195" {
			t.Errorf("native OS = %q", ss.NativeOS)
		}
	})

	t.Run("word count 10", func(t *testing.T) {
		words := make([]byte, 20)
		words[0] = smb1AndXNone
		binary.LittleEndian.PutUint16(words[14:16], uint16(len(lm)))
		data := append(append([]byte(nil), lm...), smb1String("carol", false)...)
		data = append(data, smb1String("LM-DOMAIN", false)...)
		data = append(data, smb1String("DOS", false)...)
		data = append(data, smb1String("LM1.0", false)...)
		pkt := smb1TestMessage(smb1TestHeader(smb1CommandSessionSetupAndX, false, 0), words, data)

		ss, err := smb1ParseSessionSetup(pkt)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !bytes.Equal(ss.LM, lm) {
			t.Fatalf("password field = %x, want %x", ss.LM, lm)
		}
		if ss.Account != "carol" || ss.Domain != "LM-DOMAIN" {
			t.Fatalf("identity = %q/%q", ss.Account, ss.Domain)
		}
	})
}

// TestSMB1ParseSessionSetupMalformed checks that truncated and lying messages
// are rejected or clamped instead of panicking.
func TestSMB1ParseSessionSetupMalformed(t *testing.T) {
	good := smb1TestSetupLegacy(true, make([]byte, 24), make([]byte, 24), "alice", "CORP", "OS", "LM")

	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", nil},
		{"header only", smb1TestHeader(smb1CommandSessionSetupAndX, true, 0)},
		{"unsupported word count", smb1TestMessage(smb1TestHeader(smb1CommandSessionSetupAndX, true, 0), make([]byte, 8), nil)},
		{"word count past the message", append(smb1TestHeader(smb1CommandSessionSetupAndX, true, 0), 13)},
		{"byte block truncated", good[:len(good)-20]},
		{"response lengths past the message", func() []byte {
			pkt := append([]byte(nil), good...)
			binary.LittleEndian.PutUint16(pkt[47:49], 0xffff)
			binary.LittleEndian.PutUint16(pkt[49:51], 0xffff)
			return pkt
		}()},
		{"byte count past the message", func() []byte {
			pkt := append([]byte(nil), good...)
			binary.LittleEndian.PutUint16(pkt[59:61], 0xffff)
			return pkt
		}()},
		{"no string terminators", func() []byte {
			words := make([]byte, 26)
			words[0] = smb1AndXNone
			return smb1TestMessage(smb1TestHeader(smb1CommandSessionSetupAndX, true, 0), words,
				bytes.Repeat([]byte{0x41}, 9))
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A parse error is fine; a panic or a hang is not.
			if ss, err := smb1ParseSessionSetup(tc.pkt); err == nil && ss == nil {
				t.Fatal("nil result without an error")
			}
		})
	}
}

// TestSMB1Malformed feeds whole malformed SMB1 messages to the listener.
func TestSMB1Malformed(t *testing.T) {
	addr, _, _ := smbTestServer(t)

	tests := []struct {
		name string
		pkts [][]byte
	}{
		{"header with no word count", [][]byte{smb1TestHeader(smb1CommandNegotiate, false, 0)}},
		{"unknown command", [][]byte{smb1TestMessage(smb1TestHeader(0x2b, false, 0), nil, nil)}},
		{"negotiate with an empty dialect list", [][]byte{smb1TestNegotiateRequest(false)}},
		{"session setup before negotiate with no credential", [][]byte{
			smb1TestSetupLegacy(true, nil, nil, "alice", "CORP", "OS", "LM"),
		}},
		{"session setup with a non NTLM blob", [][]byte{
			smb1TestNegotiateRequest(true, "NT LM 0.12"),
			smb1TestSetupExtended(true, 0, []byte("kerberos would go here")),
		}},
		{"truncated authenticate in a blob", [][]byte{
			smb1TestNegotiateRequest(true, "NT LM 0.12"),
			smb1TestSetupExtended(true, 0, append(append([]byte(nil), ntlmSignature...), 3, 0, 0, 0)),
		}},
		{"negotiate repeated", [][]byte{
			smb1TestNegotiateRequest(true, "NT LM 0.12"),
			smb1TestNegotiateRequest(true, "NT LM 0.12"),
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := smbTestDial(t, addr)
			for _, pkt := range tc.pkts {
				if err := smbWriteFrame(conn, nbtSessionMessage, pkt); err != nil {
					return
				}
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			answered := 0
			for {
				_, _, err := smbReadFrame(conn)
				if err == nil {
					answered++
					continue
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() && answered == 0 {
					t.Fatal("server neither answered nor closed the connection")
				}
				return
			}
		})
	}
}
