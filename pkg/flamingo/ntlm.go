package flamingo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// NTLMConfig describes the server identity flamingo presents in NTLM
// CHALLENGE messages and the fixed challenge it answers every client with.
// A constant challenge keeps captured responses verifiable and crackable
// offline with precomputed material.
type NTLMConfig struct {
	// Challenge is the 8-byte NTLM server challenge placed in every
	// CHALLENGE message and in the hashcat lines derived from the
	// responses to it.
	Challenge [8]byte

	// NetBIOSComputerName is the MsvAvNbComputerName AV_PAIR value and the
	// server name clients see in the target info.
	NetBIOSComputerName string

	// NetBIOSDomainName is the MsvAvNbDomainName AV_PAIR value. It is also
	// used as the CHALLENGE target name.
	NetBIOSDomainName string

	// DNSComputerName is the MsvAvDnsComputerName AV_PAIR value.
	DNSComputerName string

	// DNSDomainName is the MsvAvDnsDomainName AV_PAIR value.
	DNSDomainName string
}

// NTLMConf is the NTLM configuration shared by every listener that speaks
// NTLMSSP. The defaults reproduce the behaviour flamingo has always had: the
// 1122334455667788 challenge and a WIN-FLAMINGO/WORKGROUP server identity.
var NTLMConf = NTLMConfig{
	Challenge:           [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
	NetBIOSComputerName: "WIN-FLAMINGO",
	NetBIOSDomainName:   "WORKGROUP",
	DNSComputerName:     "win-flamingo",
	DNSDomainName:       "workgroup",
}

// ntlmSignature is the NTLMSSP message signature that opens every NEGOTIATE,
// CHALLENGE and AUTHENTICATE message.
var ntlmSignature = []byte("NTLMSSP\x00")

// NTLM message types.
const (
	NTLMTypeNegotiate    uint32 = 1
	NTLMTypeChallenge    uint32 = 2
	NTLMTypeAuthenticate uint32 = 3
)

// NTLM negotiate flags (MS-NLMP 2.2.2.5).
const (
	NTLMFlagUnicode                 uint32 = 0x00000001
	NTLMFlagOEM                     uint32 = 0x00000002
	NTLMFlagRequestTarget           uint32 = 0x00000004
	NTLMFlagSign                    uint32 = 0x00000010
	NTLMFlagSeal                    uint32 = 0x00000020
	NTLMFlagDatagram                uint32 = 0x00000040
	NTLMFlagLMKey                   uint32 = 0x00000080
	NTLMFlagNTLM                    uint32 = 0x00000200
	NTLMFlagAnonymous               uint32 = 0x00000800
	NTLMFlagOEMDomainSupplied       uint32 = 0x00001000
	NTLMFlagOEMWorkstationSupplied  uint32 = 0x00002000
	NTLMFlagAlwaysSign              uint32 = 0x00008000
	NTLMFlagTargetTypeDomain        uint32 = 0x00010000
	NTLMFlagTargetTypeServer        uint32 = 0x00020000
	NTLMFlagExtendedSessionSecurity uint32 = 0x00080000
	NTLMFlagIdentify                uint32 = 0x00100000
	NTLMFlagRequestNonNTSessionKey  uint32 = 0x00400000
	NTLMFlagTargetInfo              uint32 = 0x00800000
	NTLMFlagVersion                 uint32 = 0x02000000
	NTLMFlag128                     uint32 = 0x20000000
	NTLMFlagKeyExch                 uint32 = 0x40000000
	NTLMFlag56                      uint32 = 0x80000000
)

// AV_PAIR identifiers carried in CHALLENGE target info and in the NTLMv2
// client blob (MS-NLMP 2.2.2.1).
const (
	NTLMAvEOL             uint16 = 0
	NTLMAvNbComputerName  uint16 = 1
	NTLMAvNbDomainName    uint16 = 2
	NTLMAvDNSComputerName uint16 = 3
	NTLMAvDNSDomainName   uint16 = 4
	NTLMAvDNSTreeName     uint16 = 5
	NTLMAvFlags           uint16 = 6
	NTLMAvTimestamp       uint16 = 7
	NTLMAvSingleHost      uint16 = 8
	NTLMAvTargetName      uint16 = 9
	NTLMAvChannelBindings uint16 = 10
)

// NTLMAvFlagMIC is the MsvAvFlags bit a client sets when its AUTHENTICATE
// message carries a MIC.
const NTLMAvFlagMIC uint32 = 0x00000002

// Hashcat modes for the two NetNTLM response formats.
const (
	NTLMHashcatModeNetNTLMv1 = 5500
	NTLMHashcatModeNetNTLMv2 = 5600
)

// ntlmSupportedFlags is the flag set the CHALLENGE offers, intersected with
// the client's NEGOTIATE flags.
const ntlmSupportedFlags = NTLMFlagUnicode | NTLMFlagRequestTarget | NTLMFlagSign | NTLMFlagSeal |
	NTLMFlagNTLM | NTLMFlagAlwaysSign | NTLMFlagExtendedSessionSecurity | NTLMFlagTargetInfo |
	NTLMFlagVersion | NTLMFlag128 | NTLMFlagKeyExch | NTLMFlag56

// ntlmRequiredFlags is always set in the CHALLENGE regardless of what the
// client offered.
const ntlmRequiredFlags = NTLMFlagUnicode | NTLMFlagNTLM | NTLMFlagRequestTarget |
	NTLMFlagTargetTypeServer | NTLMFlagTargetInfo | NTLMFlagVersion | NTLMFlagAlwaysSign |
	NTLMFlagExtendedSessionSecurity | NTLMFlag128 | NTLMFlag56

// ntlmServerVersion is the NTLM VERSION field of the CHALLENGE
// (Windows 10.0.20348).
var ntlmServerVersion = []byte{10, 0, 0x7c, 0x4f, 0, 0, 0, 15}

// NTLMAuth is a parsed AUTHENTICATE (type 3) message.
type NTLMAuth struct {
	// User, Domain and Workstation are the identity fields, decoded from
	// UTF-16LE or OEM according to the message flags.
	User        string
	Domain      string
	Workstation string

	// LM and NT are the raw LM and NT challenge responses.
	LM []byte
	NT []byte

	// Flags is the NegotiateFlags field of the message.
	Flags uint32

	// MIC is the 16-byte message integrity code, or nil when the message
	// does not carry one.
	MIC []byte

	// Version is the client OS version as major.minor.build, empty when
	// the message has no VERSION field.
	Version string
}

// NTLMVersion names the response type: "v2" for an NTProofStr plus client
// blob, "v1" for a bare 24-byte response, and "none" when neither is present.
func (a *NTLMAuth) NTLMVersion() string {
	switch {
	case len(a.NT) > 24:
		return "v2"
	case len(a.NT) == 24:
		return "v1"
	}
	return "none"
}

// ExtendedSessionSecurity reports whether the client negotiated NTLM2 session
// security. A v1 response sent with it set is an NTLM2 session response, which
// hashcat mode 5500 still cracks from the client challenge in the LM field.
func (a *NTLMAuth) ExtendedSessionSecurity() bool {
	return a.Flags&NTLMFlagExtendedSessionSecurity != 0
}

// NTLMMessageType returns the message type of an NTLMSSP message, or 0 when
// the bytes are not an NTLMSSP message.
func NTLMMessageType(msg []byte) uint32 {
	if len(msg) < 12 || !bytes.HasPrefix(msg, ntlmSignature) {
		return 0
	}
	return binary.LittleEndian.Uint32(msg[8:12])
}

// FindNTLMSSP returns the NTLMSSP message embedded in tok, which may be a raw
// NTLM message or one wrapped in a SPNEGO/GSS-API token, and nil when tok
// carries no NTLMSSP message.
func FindNTLMSSP(tok []byte) []byte {
	if i := bytes.Index(tok, ntlmSignature); i >= 0 {
		return tok[i:]
	}
	return nil
}

// ParseNTLMNegotiate returns the flags and client OS version of a NEGOTIATE
// (type 1) message.
func ParseNTLMNegotiate(msg []byte) (flags uint32, version string) {
	if len(msg) >= 16 {
		flags = binary.LittleEndian.Uint32(msg[12:16])
	}
	if flags&NTLMFlagVersion != 0 && len(msg) >= 40 {
		version = ntlmVersionString(msg[32:40])
	}
	return flags, version
}

// NTLMChallengeMessage builds a CHALLENGE (type 2) message for a client that
// offered clientFlags, carrying the configured server challenge and an AV_PAIR
// target info block naming the configured server identity. A zero clientFlags
// offers the full supported set.
func NTLMChallengeMessage(clientFlags uint32) []byte {
	flags := uint32(ntlmSupportedFlags)
	if clientFlags != 0 {
		flags = clientFlags & ntlmSupportedFlags
	}
	flags |= ntlmRequiredFlags

	target := utf16Bytes(NTLMConf.NetBIOSDomainName)
	var info []byte
	av := func(id uint16, v []byte) {
		info = binary.LittleEndian.AppendUint16(info, id)
		info = binary.LittleEndian.AppendUint16(info, uint16(len(v)))
		info = append(info, v...)
	}
	av(NTLMAvNbDomainName, target)
	av(NTLMAvNbComputerName, utf16Bytes(NTLMConf.NetBIOSComputerName))
	av(NTLMAvDNSDomainName, utf16Bytes(NTLMConf.DNSDomainName))
	av(NTLMAvDNSComputerName, utf16Bytes(NTLMConf.DNSComputerName))
	av(NTLMAvTimestamp, binary.LittleEndian.AppendUint64(nil, winFiletime(time.Now())))
	av(NTLMAvEOL, nil)

	m := make([]byte, 56+len(target)+len(info))
	copy(m[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(m[8:12], NTLMTypeChallenge)
	binary.LittleEndian.PutUint16(m[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(m[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(m[16:20], 56)
	binary.LittleEndian.PutUint32(m[20:24], flags)
	copy(m[24:32], NTLMConf.Challenge[:])
	binary.LittleEndian.PutUint16(m[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(m[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(m[44:48], uint32(56+len(target)))
	copy(m[48:56], ntlmServerVersion)
	copy(m[56:], target)
	copy(m[56+len(target):], info)
	return m
}

// ParseNTLMAuthenticate decodes the identity fields, challenge responses,
// flags, MIC and client version of an AUTHENTICATE (type 3) message. It never
// panics: every security buffer is bounds checked against the message and
// truncated or malformed input returns an error.
func ParseNTLMAuthenticate(msg []byte) (*NTLMAuth, error) {
	if len(msg) < 52 {
		return nil, errors.New("short NTLM AUTHENTICATE")
	}
	if !bytes.HasPrefix(msg, ntlmSignature) {
		return nil, errors.New("not an NTLMSSP message")
	}
	if t := binary.LittleEndian.Uint32(msg[8:12]); t != NTLMTypeAuthenticate {
		return nil, fmt.Errorf("NTLM message type %d, want %d", t, NTLMTypeAuthenticate)
	}

	a := &NTLMAuth{}
	a.LM = ntlmSecBuf(msg, 12)
	a.NT = ntlmSecBuf(msg, 20)

	// Win9x-era clients omit the session key, flags and version fields and
	// start their payload at offset 52. Everything after the workstation
	// buffer is only present when the payload starts beyond it.
	lowest := ntlmLowestPayload(msg, 12, 20, 28, 36, 44)
	off := 52
	if lowest > 52 {
		if sk := ntlmLowestPayload(msg, 52); sk > 0 && sk < lowest {
			lowest = sk
		}
		if len(msg) >= 64 {
			a.Flags = binary.LittleEndian.Uint32(msg[60:64])
		}
		off = 64
		if a.Flags&NTLMFlagVersion != 0 && len(msg) >= 72 {
			a.Version = ntlmVersionString(msg[64:72])
			off = 72
		}
		// MS-NLMP ties the MIC to the MsvAvFlags bit in the client blob,
		// but plenty of clients leave room for one without setting it, so
		// require both space before the payload and a MIC that is not a
		// run of zero padding.
		if lowest >= off+16 && len(msg) >= off+16 {
			if mic := msg[off : off+16]; ntlmWantsMIC(a.NT) || !ntlmAllZero(mic) {
				a.MIC = mic
			}
		}
	}

	str := func(b []byte) string {
		if a.Flags&NTLMFlagUnicode != 0 || a.Flags == 0 {
			return utf16String(b)
		}
		return strings.TrimRight(string(b), "\x00")
	}
	a.Domain = str(ntlmSecBuf(msg, 28))
	a.User = str(ntlmSecBuf(msg, 36))
	a.Workstation = str(ntlmSecBuf(msg, 44))
	return a, nil
}

// NTLMHashcat formats a parsed AUTHENTICATE message as a hashcat line and
// returns the mode that cracks it: mode 5600 (NetNTLMv2,
// user::domain:challenge:NTProofStr:blob) for a v2 response and mode 5500
// (NetNTLMv1, user::workstation:LM:NT:challenge) for a v1 response. A message
// without a usable NT response yields an empty line and a zero mode.
func NTLMHashcat(a *NTLMAuth) (string, int) {
	return NTLMHashcatChallenge(a, NTLMConf.Challenge[:])
}

// NTLMHashcatChallenge is NTLMHashcat against an explicit server challenge.
//
// The challenge is a parameter because it is not always flamingo's own. A
// relayed exchange answers the victim with the *target's* challenge, so the
// response the victim computes is only crackable against that challenge;
// formatting it against NTLMConf.Challenge would emit a line that looks right
// and can never crack. A nil or short challenge falls back to the configured
// one, which is what every capture-only listener uses.
func NTLMHashcatChallenge(a *NTLMAuth, challenge []byte) (string, int) {
	if a == nil {
		return "", 0
	}
	if len(challenge) != 8 {
		challenge = NTLMConf.Challenge[:]
	}
	switch a.NTLMVersion() {
	case "v1":
		return fmt.Sprintf("%s::%s:%x:%x:%x", a.User, a.Workstation, a.LM, a.NT,
			challenge), NTLMHashcatModeNetNTLMv1
	case "v2":
		return fmt.Sprintf("%s::%s:%x:%x:%x", a.User, a.Domain, challenge,
			a.NT[:16], a.NT[16:]), NTLMHashcatModeNetNTLMv2
	}
	return "", 0
}

// NTLMServerChallenge returns the 8-byte server challenge carried by a
// CHALLENGE (type 2) message, or nil when msg is not one.
func NTLMServerChallenge(msg []byte) []byte {
	if len(msg) < 32 || NTLMMessageType(msg) != NTLMTypeChallenge {
		return nil
	}
	return msg[24:32]
}

// NTLMAvPairs decodes an AV_PAIR list into a map of identifier to raw value,
// stopping at the end-of-list pair or at the first truncated entry.
func NTLMAvPairs(info []byte) map[uint16][]byte {
	pairs := make(map[uint16][]byte)
	for idx := 0; idx+4 <= len(info); {
		id := binary.LittleEndian.Uint16(info[idx:])
		n := int(binary.LittleEndian.Uint16(info[idx+2:]))
		idx += 4
		if id == NTLMAvEOL {
			break
		}
		if idx+n > len(info) {
			break
		}
		pairs[id] = info[idx : idx+n]
		idx += n
	}
	return pairs
}

// ntlmWantsMIC reports whether an NTLMv2 response advertises a MIC through the
// MsvAvFlags pair of its client blob.
func ntlmWantsMIC(nt []byte) bool {
	if len(nt) <= 44 {
		return false
	}
	v, ok := NTLMAvPairs(nt[44:])[NTLMAvFlags]
	if !ok || len(v) < 4 {
		return false
	}
	return binary.LittleEndian.Uint32(v)&NTLMAvFlagMIC != 0
}

// ntlmAllZero reports whether b is entirely zero bytes.
func ntlmAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ntlmSecBuf reads an NTLM security buffer (length, max length, offset) at off
// and returns the bytes it points to when they are in bounds.
func ntlmSecBuf(msg []byte, off int) []byte {
	if off+8 > len(msg) {
		return nil
	}
	n := int(binary.LittleEndian.Uint16(msg[off : off+2]))
	start := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
	if start < 0 || n < 0 || start > len(msg) || n > len(msg)-start {
		return nil
	}
	return msg[start : start+n]
}

// ntlmLowestPayload returns the lowest payload offset of the non-empty
// security buffers at the given header offsets, or 0 when there are none.
func ntlmLowestPayload(msg []byte, offsets ...int) int {
	lowest := 0
	for _, off := range offsets {
		if off+8 > len(msg) {
			continue
		}
		if binary.LittleEndian.Uint16(msg[off:off+2]) == 0 {
			continue
		}
		start := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
		if lowest == 0 || start < lowest {
			lowest = start
		}
	}
	return lowest
}

// ntlmVersionString formats an NTLM VERSION field as major.minor.build.
func ntlmVersionString(v []byte) string {
	if len(v) < 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.LittleEndian.Uint16(v[2:4]))
}
