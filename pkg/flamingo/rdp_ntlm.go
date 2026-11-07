package flamingo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// RDPNTLMChallenge is the fixed 8-byte NTLM server challenge presented to
// every CredSSP client. A constant challenge, as with the existing VNC and
// HTTP NTLM collectors, keeps captured responses verifiable and crackable
// offline with precomputed material.
var RDPNTLMChallenge = [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// Server identity presented in the NTLM CHALLENGE target info.
const (
	rdpComputerName = "WIN-FLAMINGO"
	rdpDomain       = "WORKGROUP"
)

// rdpNTLMSig is the NTLMSSP message signature.
var rdpNTLMSig = []byte("NTLMSSP\x00")

// NTLM negotiate flags.
const (
	rdpNTLMUnicode       uint32 = 0x00000001
	rdpNTLMRequestTarget uint32 = 0x00000004
	rdpNTLMSign          uint32 = 0x00000010
	rdpNTLMSeal          uint32 = 0x00000020
	rdpNTLMNTLM          uint32 = 0x00000200
	rdpNTLMAlwaysSign    uint32 = 0x00008000
	rdpNTLMTargetServer  uint32 = 0x00020000
	rdpNTLMExtendedSec   uint32 = 0x00080000
	rdpNTLMTargetInfo    uint32 = 0x00800000
	rdpNTLMVersion       uint32 = 0x02000000
	rdpNTLM128           uint32 = 0x20000000
	rdpNTLMKeyExch       uint32 = 0x40000000
	rdpNTLM56            uint32 = 0x80000000
)

// AV_PAIR ids in the CHALLENGE target info.
const (
	rdpAVEOL             = 0
	rdpAVNbComputerName  = 1
	rdpAVNbDomainName    = 2
	rdpAVDnsComputerName = 3
	rdpAVDnsDomainName   = 4
	rdpAVTimestamp       = 7
)

// rdpNTLMSupported is the flag set the challenge offers, intersected with
// the client's.
const rdpNTLMSupported = rdpNTLMUnicode | rdpNTLMRequestTarget | rdpNTLMSign | rdpNTLMSeal |
	rdpNTLMNTLM | rdpNTLMAlwaysSign | rdpNTLMExtendedSec | rdpNTLMTargetInfo | rdpNTLMVersion |
	rdpNTLM128 | rdpNTLMKeyExch | rdpNTLM56

// rdpNTLMRequired is always set in the challenge.
const rdpNTLMRequired = rdpNTLMUnicode | rdpNTLMNTLM | rdpNTLMRequestTarget | rdpNTLMTargetServer |
	rdpNTLMTargetInfo | rdpNTLMVersion | rdpNTLMAlwaysSign | rdpNTLMExtendedSec | rdpNTLM128 | rdpNTLM56

// rdpNTLMServerVersion is the NTLM VERSION field of the challenge
// (Windows 10.0.20348).
var rdpNTLMServerVersion = []byte{10, 0, 0x7c, 0x4f, 0, 0, 0, 15}

// rdpNTLMAuth is a parsed AUTHENTICATE message.
type rdpNTLMAuth struct {
	user, domain, workstation string
	lm, nt                    []byte
	flags                     uint32
	version                   string
}

// ntlmVersion names the response type: v2 (NTProofStr plus client blob),
// v1 (24-byte response), or none.
func (a *rdpNTLMAuth) ntlmVersion() string {
	switch {
	case len(a.nt) > 24:
		return "v2"
	case len(a.nt) == 24:
		return "v1"
	}
	return "none"
}

// rdpNTLMType returns the message type of an NTLMSSP message, or 0.
func rdpNTLMType(msg []byte) uint32 {
	if len(msg) < 12 || !bytes.HasPrefix(msg, rdpNTLMSig) {
		return 0
	}
	return binary.LittleEndian.Uint32(msg[8:12])
}

// rdpNTLMFind returns the NTLMSSP message in a CredSSP nego token, which is
// either raw or wrapped in SPNEGO.
func rdpNTLMFind(tok []byte) []byte {
	if i := bytes.Index(tok, rdpNTLMSig); i >= 0 {
		return tok[i:]
	}
	return nil
}

// rdpNTLMParseNegotiate returns the flags and client version of a NEGOTIATE
// message.
func rdpNTLMParseNegotiate(msg []byte) (flags uint32, version string) {
	if len(msg) >= 16 {
		flags = binary.LittleEndian.Uint32(msg[12:16])
	}
	if flags&rdpNTLMVersion != 0 && len(msg) >= 40 {
		version = rdpNTLMVersionString(msg[32:40])
	}
	return flags, version
}

// rdpNTLMVersionString formats an NTLM VERSION field as major.minor.build.
func rdpNTLMVersionString(v []byte) string {
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.LittleEndian.Uint16(v[2:4]))
}

// rdpNTLMChallengeMessage builds a CHALLENGE message for the client's
// NEGOTIATE flags carrying the fixed server challenge.
func rdpNTLMChallengeMessage(client uint32) []byte {
	flags := uint32(rdpNTLMSupported)
	if client != 0 {
		flags = client & rdpNTLMSupported
	}
	flags |= rdpNTLMRequired

	target := rdpUTF16Bytes(rdpDomain)
	var info []byte
	av := func(id uint16, v []byte) {
		info = binary.LittleEndian.AppendUint16(info, id)
		info = binary.LittleEndian.AppendUint16(info, uint16(len(v)))
		info = append(info, v...)
	}
	av(rdpAVNbDomainName, target)
	av(rdpAVNbComputerName, rdpUTF16Bytes(rdpComputerName))
	av(rdpAVDnsDomainName, rdpUTF16Bytes(strings.ToLower(rdpDomain)))
	av(rdpAVDnsComputerName, rdpUTF16Bytes(strings.ToLower(rdpComputerName)))
	av(rdpAVTimestamp, binary.LittleEndian.AppendUint64(nil, rdpFiletime(time.Now())))
	av(rdpAVEOL, nil)

	m := make([]byte, 56+len(target)+len(info))
	copy(m[0:8], rdpNTLMSig)
	binary.LittleEndian.PutUint32(m[8:12], 2)
	binary.LittleEndian.PutUint16(m[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(m[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(m[16:20], 56)
	binary.LittleEndian.PutUint32(m[20:24], flags)
	copy(m[24:32], RDPNTLMChallenge[:])
	binary.LittleEndian.PutUint16(m[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(m[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(m[44:48], uint32(56+len(target)))
	copy(m[48:56], rdpNTLMServerVersion)
	copy(m[56:], target)
	copy(m[56+len(target):], info)
	return m
}

// rdpNTLMParseAuthenticate decodes the identity fields and responses of an
// AUTHENTICATE message.
func rdpNTLMParseAuthenticate(msg []byte) (*rdpNTLMAuth, error) {
	if len(msg) < 64 {
		return nil, errors.New("short NTLM AUTHENTICATE")
	}
	a := &rdpNTLMAuth{flags: binary.LittleEndian.Uint32(msg[60:64])}
	str := func(b []byte) string {
		if a.flags&rdpNTLMUnicode != 0 {
			return rdpUTF16String(b)
		}
		return strings.TrimRight(string(b), "\x00")
	}
	a.lm = rdpNTLMSecBuf(msg, 12)
	a.nt = rdpNTLMSecBuf(msg, 20)
	a.domain = str(rdpNTLMSecBuf(msg, 28))
	a.user = str(rdpNTLMSecBuf(msg, 36))
	a.workstation = str(rdpNTLMSecBuf(msg, 44))
	if a.flags&rdpNTLMVersion != 0 && len(msg) >= 72 {
		a.version = rdpNTLMVersionString(msg[64:72])
	}
	return a, nil
}

// rdpNTLMSecBuf reads an NTLM security buffer (length, max length, offset)
// at off and returns the bytes it points to when they are in bounds.
func rdpNTLMSecBuf(msg []byte, off int) []byte {
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

// rdpNTLMHashcat formats the response as a hashcat line in the same layout
// the HTTP NTLM collector emits: mode 5500 (user::workstation:lm:nt:challenge)
// for NTLMv1 and mode 5600 (user::domain:challenge:proof:blob) for NTLMv2.
func rdpNTLMHashcat(a *rdpNTLMAuth) string {
	switch a.ntlmVersion() {
	case "v1":
		return fmt.Sprintf("%s::%s:%x:%x:%x", a.user, a.workstation, a.lm, a.nt, RDPNTLMChallenge[:])
	case "v2":
		return fmt.Sprintf("%s::%s:%x:%x:%x", a.user, a.domain, RDPNTLMChallenge[:], a.nt[:16], a.nt[16:])
	}
	return ""
}

// rdpUTF16String decodes UTF-16LE, dropping trailing NULs and an odd byte.
func rdpUTF16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// rdpUTF16Bytes encodes s as UTF-16LE.
func rdpUTF16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// rdpFiletime converts t to a Windows FILETIME.
func rdpFiletime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}
