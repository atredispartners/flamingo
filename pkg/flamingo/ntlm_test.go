package flamingo

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/md4"
)

// ntlmTestAuthMsg builds an AUTHENTICATE (type 3) message carrying the given
// identity fields and responses. Strings are encoded UTF-16LE and the flags
// always claim Unicode plus a VERSION field, as a modern client does. When
// mic is non-nil it is placed in the 16 bytes between the VERSION field and
// the payload.
func ntlmTestAuthMsg(user, domain, ws string, lm, nt, mic []byte, extraFlags uint32) []byte {
	hdr := 72
	if mic != nil {
		hdr += 16
	}
	m := make([]byte, hdr)
	copy(m, ntlmSignature)
	binary.LittleEndian.PutUint32(m[8:], NTLMTypeAuthenticate)

	var payload []byte
	put := func(at int, b []byte) {
		binary.LittleEndian.PutUint16(m[at:], uint16(len(b)))
		binary.LittleEndian.PutUint16(m[at+2:], uint16(len(b)))
		binary.LittleEndian.PutUint32(m[at+4:], uint32(len(m)+len(payload)))
		payload = append(payload, b...)
	}
	put(12, lm)
	put(20, nt)
	put(28, utf16Bytes(domain))
	put(36, utf16Bytes(user))
	put(44, utf16Bytes(ws))
	put(52, nil)

	flags := NTLMFlagUnicode | NTLMFlagRequestTarget | NTLMFlagNTLM | NTLMFlagAlwaysSign |
		NTLMFlagTargetInfo | NTLMFlagVersion | NTLMFlag128 | NTLMFlag56 | extraFlags
	binary.LittleEndian.PutUint32(m[60:], flags)
	copy(m[64:72], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})
	if mic != nil {
		copy(m[72:88], mic)
	}
	return append(m, payload...)
}

// ntlmTestNTOWFv2 is NTOWFv2(password, user, domain).
func ntlmTestNTOWFv2(password, user, domain string) []byte {
	h := md4.New()
	h.Write(utf16Bytes(password))
	m := hmac.New(md5.New, h.Sum(nil))
	m.Write(utf16Bytes(strings.ToUpper(user) + domain))
	return m.Sum(nil)
}

// ntlmTestV2Proof computes the NTProofStr for an NTLMv2 client blob.
func ntlmTestV2Proof(password, user, domain string, challenge, blob []byte) []byte {
	m := hmac.New(md5.New, ntlmTestNTOWFv2(password, user, domain))
	m.Write(challenge)
	m.Write(blob)
	return m.Sum(nil)
}

// ntlmTestV2Blob builds an NTLMv2_CLIENT_CHALLENGE around the target info of
// a CHALLENGE message, optionally appending an MsvAvFlags pair that announces
// a MIC.
func ntlmTestV2Blob(targetInfo []byte, withMICFlag bool) []byte {
	info := append([]byte(nil), targetInfo...)
	if withMICFlag {
		info = binary.LittleEndian.AppendUint16(info, NTLMAvFlags)
		info = binary.LittleEndian.AppendUint16(info, 4)
		info = binary.LittleEndian.AppendUint32(info, NTLMAvFlagMIC)
		info = binary.LittleEndian.AppendUint16(info, NTLMAvEOL)
		info = binary.LittleEndian.AppendUint16(info, 0)
	}
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = binary.LittleEndian.AppendUint64(blob, winFiletime(time.Now()))
	blob = append(blob, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, info...)
	return append(blob, 0, 0, 0, 0)
}

// ntlmTestDESL is the DESL primitive of MS-NLMP, used to build a genuine
// NTLMv1 response from a password and an 8-byte challenge.
func ntlmTestDESL(key, data []byte) []byte {
	k := make([]byte, 21)
	copy(k, key)
	out := make([]byte, 0, 24)
	for i := 0; i < 21; i += 7 {
		var b [8]byte
		s := k[i : i+7]
		b[0] = s[0]
		b[1] = s[0]<<7 | s[1]>>1
		b[2] = s[1]<<6 | s[2]>>2
		b[3] = s[2]<<5 | s[3]>>3
		b[4] = s[3]<<4 | s[4]>>4
		b[5] = s[4]<<3 | s[5]>>5
		b[6] = s[5]<<2 | s[6]>>6
		b[7] = s[6] << 1
		c, err := des.NewCipher(b[:])
		if err != nil {
			panic(err)
		}
		block := make([]byte, 8)
		c.Encrypt(block, data)
		out = append(out, block...)
	}
	return out
}

// ntlmTestV1Response is the NTLMv1 NT response for a password and challenge.
func ntlmTestV1Response(password string, challenge []byte) []byte {
	h := md4.New()
	h.Write(utf16Bytes(password))
	return ntlmTestDESL(h.Sum(nil), challenge)
}

// TestNTLMHashcatFormats covers the two hashcat layouts the collectors emit:
// mode 5600 puts the domain in field two, mode 5500 the workstation, and a
// message with no usable NT response yields nothing at all.
func TestNTLMHashcatFormats(t *testing.T) {
	chal := hex.EncodeToString(NTLMConf.Challenge[:])
	proof := bytes.Repeat([]byte{0xaa}, 16)
	blob := bytes.Repeat([]byte{0xbb}, 28)
	lm24 := bytes.Repeat([]byte{0xcc}, 24)
	nt24 := bytes.Repeat([]byte{0xdd}, 24)

	cases := []struct {
		name     string
		auth     *NTLMAuth
		wantLine string
		wantMode int
	}{
		{
			name: "netntlmv2 uses the domain",
			auth: &NTLMAuth{
				User: "alice", Domain: "CORP", Workstation: "WS01",
				LM: bytes.Repeat([]byte{0x11}, 24),
				NT: append(append([]byte(nil), proof...), blob...),
			},
			wantLine: "alice::CORP:" + chal + ":" + hex.EncodeToString(proof) + ":" +
				hex.EncodeToString(blob),
			wantMode: NTLMHashcatModeNetNTLMv2,
		},
		{
			name: "netntlmv2 with an empty domain",
			auth: &NTLMAuth{
				User: "alice",
				NT:   append(append([]byte(nil), proof...), blob...),
			},
			wantLine: "alice:::" + chal + ":" + hex.EncodeToString(proof) + ":" +
				hex.EncodeToString(blob),
			wantMode: NTLMHashcatModeNetNTLMv2,
		},
		{
			name: "netntlmv1 uses the workstation",
			auth: &NTLMAuth{
				User: "bob", Domain: "CORP", Workstation: "WS02",
				LM: lm24, NT: nt24,
			},
			wantLine: "bob::WS02:" + hex.EncodeToString(lm24) + ":" +
				hex.EncodeToString(nt24) + ":" + chal,
			wantMode: NTLMHashcatModeNetNTLMv1,
		},
		{
			name: "netntlmv1 with extended session security keeps the layout",
			auth: &NTLMAuth{
				User: "bob", Workstation: "WS02",
				LM:    append(bytes.Repeat([]byte{0x7f}, 8), make([]byte, 16)...),
				NT:    nt24,
				Flags: NTLMFlagExtendedSessionSecurity,
			},
			wantLine: "bob::WS02:" + hex.EncodeToString(
				append(bytes.Repeat([]byte{0x7f}, 8), make([]byte, 16)...)) + ":" +
				hex.EncodeToString(nt24) + ":" + chal,
			wantMode: NTLMHashcatModeNetNTLMv1,
		},
		{
			name:     "anonymous bind has no response to crack",
			auth:     &NTLMAuth{User: "guest"},
			wantLine: "",
			wantMode: 0,
		},
		{
			name:     "a nil message is not a credential",
			auth:     nil,
			wantLine: "",
			wantMode: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, mode := NTLMHashcat(tc.auth)
			if line != tc.wantLine {
				t.Errorf("line = %q, want %q", line, tc.wantLine)
			}
			if mode != tc.wantMode {
				t.Errorf("mode = %d, want %d", mode, tc.wantMode)
			}
			if tc.wantLine != "" && len(strings.Split(line, ":")) != 6 {
				t.Errorf("line %q is not six colon-separated fields", line)
			}
		})
	}
}

// TestNTLMParseAuthenticate checks that the identity fields, responses, flags,
// version and MIC of well-formed messages are recovered.
func TestNTLMParseAuthenticate(t *testing.T) {
	proof := bytes.Repeat([]byte{0xaa}, 16)
	mic := bytes.Repeat([]byte{0x5a}, 16)

	t.Run("ntlmv2 identity fields", func(t *testing.T) {
		blob := ntlmTestV2Blob(nil, false)
		nt := append(append([]byte(nil), proof...), blob...)
		a, err := ParseNTLMAuthenticate(
			ntlmTestAuthMsg("alice", "CORP", "WS01", make([]byte, 24), nt, nil, 0))
		if err != nil {
			t.Fatalf("parse: %s", err)
		}
		if a.User != "alice" || a.Domain != "CORP" || a.Workstation != "WS01" {
			t.Errorf("identity = %q/%q/%q", a.User, a.Domain, a.Workstation)
		}
		if !bytes.Equal(a.NT, nt) {
			t.Errorf("NT response round-trip failed")
		}
		if a.NTLMVersion() != "v2" {
			t.Errorf("NTLMVersion = %q, want v2", a.NTLMVersion())
		}
		if a.Version != "10.0.19043" {
			t.Errorf("client version = %q, want 10.0.19043", a.Version)
		}
		if a.MIC != nil {
			t.Errorf("MIC = %x, want none", a.MIC)
		}
	})

	t.Run("ntlmv1 with extended session security", func(t *testing.T) {
		lm := append(bytes.Repeat([]byte{0x7f}, 8), make([]byte, 16)...)
		nt := bytes.Repeat([]byte{0xdd}, 24)
		a, err := ParseNTLMAuthenticate(ntlmTestAuthMsg("bob", "CORP", "WS02", lm, nt, nil,
			NTLMFlagExtendedSessionSecurity))
		if err != nil {
			t.Fatalf("parse: %s", err)
		}
		if a.NTLMVersion() != "v1" {
			t.Errorf("NTLMVersion = %q, want v1", a.NTLMVersion())
		}
		if !a.ExtendedSessionSecurity() {
			t.Error("ExtendedSessionSecurity = false, want true")
		}
		if !bytes.Equal(a.LM, lm) {
			t.Error("LM response round-trip failed")
		}
		line, mode := NTLMHashcat(a)
		if mode != NTLMHashcatModeNetNTLMv1 {
			t.Fatalf("mode = %d, want %d", mode, NTLMHashcatModeNetNTLMv1)
		}
		// hashcat recovers the NTLM2 session challenge from the client
		// challenge in the LM field, so it must survive verbatim.
		if !strings.Contains(line, hex.EncodeToString(lm)) {
			t.Errorf("line %q dropped the client challenge", line)
		}
	})

	t.Run("message integrity code", func(t *testing.T) {
		blob := ntlmTestV2Blob(nil, true)
		nt := append(append([]byte(nil), proof...), blob...)
		a, err := ParseNTLMAuthenticate(
			ntlmTestAuthMsg("alice", "CORP", "WS01", make([]byte, 24), nt, mic, 0))
		if err != nil {
			t.Fatalf("parse: %s", err)
		}
		if !bytes.Equal(a.MIC, mic) {
			t.Errorf("MIC = %x, want %x", a.MIC, mic)
		}
		if a.User != "alice" {
			t.Errorf("user = %q, want alice (MIC shifted the payload)", a.User)
		}
	})
}

// TestNTLMParseAuthenticateMalformed feeds truncated and corrupt messages to
// the parser, which must return an error or an empty field rather than panic.
func TestNTLMParseAuthenticateMalformed(t *testing.T) {
	good := ntlmTestAuthMsg("alice", "CORP", "WS01", make([]byte, 24),
		bytes.Repeat([]byte{0xaa}, 48), nil, 0)

	badOffset := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(badOffset[24:], 0xffffff00)
	badLength := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(badLength[20:], 0xffff)

	cases := []struct {
		name    string
		msg     []byte
		wantErr bool
	}{
		{name: "nil", msg: nil, wantErr: true},
		{name: "empty", msg: []byte{}, wantErr: true},
		{name: "signature only", msg: ntlmSignature, wantErr: true},
		{name: "header truncated", msg: good[:51], wantErr: true},
		{name: "not ntlmssp", msg: bytes.Repeat([]byte{0x41}, 96), wantErr: true},
		{
			name:    "wrong message type",
			msg:     append(append([]byte(nil), ntlmSignature...), 1, 0, 0, 0, 0, 0, 0, 0),
			wantErr: true,
		},
		{name: "payload cut off", msg: good[:len(good)-10]},
		{name: "security buffer offset past the end", msg: badOffset},
		{name: "security buffer length past the end", msg: badLength},
		{name: "headers only", msg: good[:72]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseNTLMAuthenticate(tc.msg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parse returned %+v, want an error", a)
				}
				return
			}
			if err != nil {
				return
			}
			// Formatting a partially recovered message must not panic
			// either.
			NTLMHashcat(a)
		})
	}
}

// TestNTLMChallengeRoundTrip builds a CHALLENGE, answers it with a genuine
// NTLMv2 response computed over its target info, parses the AUTHENTICATE back
// and verifies the hashcat line recovers the known password from its own
// fields, the way mode 5600 would.
func TestNTLMChallengeRoundTrip(t *testing.T) {
	const user, domain, ws, secret = "Administrator", "CORP", "ATTACKER", "Winter2026!"

	clientFlags := NTLMFlagUnicode | NTLMFlagRequestTarget | NTLMFlagNTLM |
		NTLMFlagExtendedSessionSecurity | NTLMFlagVersion
	chal := NTLMChallengeMessage(clientFlags)

	if NTLMMessageType(chal) != NTLMTypeChallenge {
		t.Fatalf("message type = %d, want %d", NTLMMessageType(chal), NTLMTypeChallenge)
	}
	if got := chal[24:32]; !bytes.Equal(got, NTLMConf.Challenge[:]) {
		t.Fatalf("server challenge = %x, want %x", got, NTLMConf.Challenge[:])
	}
	if target := utf16String(ntlmSecBuf(chal, 12)); target != NTLMConf.NetBIOSDomainName {
		t.Fatalf("target name = %q, want %q", target, NTLMConf.NetBIOSDomainName)
	}

	// The CHALLENGE must be findable inside a SPNEGO-style wrapper too.
	wrapped := append([]byte{0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}, chal...)
	if found := FindNTLMSSP(wrapped); !bytes.Equal(found, chal) {
		t.Fatal("FindNTLMSSP did not recover the message from a GSS wrapper")
	}
	if FindNTLMSSP([]byte("no ntlm here")) != nil {
		t.Fatal("FindNTLMSSP found a message in unrelated bytes")
	}

	info := ntlmSecBuf(chal, 40)
	pairs := NTLMAvPairs(info)
	for id, want := range map[uint16]string{
		NTLMAvNbDomainName:    NTLMConf.NetBIOSDomainName,
		NTLMAvNbComputerName:  NTLMConf.NetBIOSComputerName,
		NTLMAvDNSDomainName:   NTLMConf.DNSDomainName,
		NTLMAvDNSComputerName: NTLMConf.DNSComputerName,
	} {
		if got := utf16String(pairs[id]); got != want {
			t.Errorf("AV_PAIR %d = %q, want %q", id, got, want)
		}
	}
	if len(pairs[NTLMAvTimestamp]) != 8 {
		t.Error("CHALLENGE carries no timestamp AV_PAIR")
	}

	// Answer as a client would: NTProofStr over the server challenge and
	// the client blob built from the server's own target info.
	challenge := chal[24:32]
	blob := ntlmTestV2Blob(info, false)
	proof := ntlmTestV2Proof(secret, user, domain, challenge, blob)
	nt := append(append([]byte(nil), proof...), blob...)

	a, err := ParseNTLMAuthenticate(ntlmTestAuthMsg(user, domain, ws, make([]byte, 24), nt, nil, 0))
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	line, mode := NTLMHashcat(a)
	if mode != NTLMHashcatModeNetNTLMv2 {
		t.Fatalf("mode = %d, want %d", mode, NTLMHashcatModeNetNTLMv2)
	}

	parts := strings.Split(line, ":")
	if len(parts) != 6 {
		t.Fatalf("hashcat line has %d fields: %q", len(parts), line)
	}
	gotChal, _ := hex.DecodeString(parts[3])
	gotProof, _ := hex.DecodeString(parts[4])
	gotBlob, _ := hex.DecodeString(parts[5])
	if !bytes.Equal(ntlmTestV2Proof(secret, parts[0], parts[2], gotChal, gotBlob), gotProof) {
		t.Error("captured hashcat line does not recover the known password")
	}
}

// TestNTLMChallengeRoundTripV1 answers the CHALLENGE with a genuine NTLMv1
// response and verifies the mode 5500 line recovers the known password.
func TestNTLMChallengeRoundTripV1(t *testing.T) {
	const user, ws, secret = "legacy", "WIN98", "Password1"

	chal := NTLMChallengeMessage(NTLMFlagUnicode | NTLMFlagNTLM)
	challenge := chal[24:32]
	nt := ntlmTestV1Response(secret, challenge)

	a, err := ParseNTLMAuthenticate(ntlmTestAuthMsg(user, "", ws, make([]byte, 24), nt, nil, 0))
	if err != nil {
		t.Fatalf("parse: %s", err)
	}
	line, mode := NTLMHashcat(a)
	if mode != NTLMHashcatModeNetNTLMv1 {
		t.Fatalf("mode = %d, want %d", mode, NTLMHashcatModeNetNTLMv1)
	}

	parts := strings.Split(line, ":")
	if len(parts) != 6 {
		t.Fatalf("hashcat line has %d fields: %q", len(parts), line)
	}
	if parts[2] != ws {
		t.Errorf("field 2 = %q, want the workstation %q", parts[2], ws)
	}
	gotNT, _ := hex.DecodeString(parts[4])
	gotChal, _ := hex.DecodeString(parts[5])
	if !bytes.Equal(ntlmTestV1Response(secret, gotChal), gotNT) {
		t.Error("captured hashcat line does not recover the known password")
	}
}

// TestNTLMMessageType checks the type probe used by the listeners to drive
// their NTLM state machines.
func TestNTLMMessageType(t *testing.T) {
	negotiate := make([]byte, 40)
	copy(negotiate, ntlmSignature)
	binary.LittleEndian.PutUint32(negotiate[8:], NTLMTypeNegotiate)
	binary.LittleEndian.PutUint32(negotiate[12:], NTLMFlagUnicode|NTLMFlagNTLM|NTLMFlagVersion)
	copy(negotiate[32:40], []byte{10, 0, 0x63, 0x4a, 0, 0, 0, 15})

	cases := []struct {
		name string
		msg  []byte
		want uint32
	}{
		{name: "negotiate", msg: negotiate, want: NTLMTypeNegotiate},
		{name: "challenge", msg: NTLMChallengeMessage(0), want: NTLMTypeChallenge},
		{
			name: "authenticate",
			msg:  ntlmTestAuthMsg("a", "b", "c", nil, nil, nil, 0),
			want: NTLMTypeAuthenticate,
		},
		{name: "nil", msg: nil, want: 0},
		{name: "short", msg: ntlmSignature, want: 0},
		{name: "not ntlmssp", msg: bytes.Repeat([]byte{0x41}, 32), want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NTLMMessageType(tc.msg); got != tc.want {
				t.Errorf("NTLMMessageType = %d, want %d", got, tc.want)
			}
		})
	}

	flags, version := ParseNTLMNegotiate(negotiate)
	if flags&NTLMFlagNTLM == 0 {
		t.Errorf("negotiate flags = %#08x, want the NTLM bit", flags)
	}
	if version != "10.0.19043" {
		t.Errorf("client version = %q, want 10.0.19043", version)
	}
	if _, v := ParseNTLMNegotiate(negotiate[:12]); v != "" {
		t.Errorf("truncated negotiate reported version %q", v)
	}
}
