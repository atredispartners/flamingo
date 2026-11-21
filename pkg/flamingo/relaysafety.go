package flamingo

import (
	"fmt"
	"math/bits"
)

// upstreamType3Safe reports whether gopacket's pkg/relay can be handed an
// attacker-supplied NTLM AUTHENTICATE message without risking a panic.
//
// relay.extractNTLMType3Info (client.go:544) bounds-checks a security buffer
// with int arithmetic and then slices with the raw uint32:
//
//	if int(domainOffset)+int(domainLen) <= len(type3) {
//	        raw := type3[domainOffset : domainOffset+uint32(domainLen)]
//
// Where int is 64 bits the check is sound. Where int is 32 bits, an offset
// such as 0xFFFFFFF0 converts to a negative number, the check passes, and the
// slice expression then indexes past the end of the buffer and panics.
//
// This is reachable from the capture path, not only from relaying:
// rpc_server.go:382 and :474 and http_server.go:369 (which the WinRM servers
// wrap) all call it on a message supplied by whoever connected. The panic
// happens on an upstream goroutine, so no recover() of ours can contain it,
// and a panic on any goroutine takes the whole process down. One crafted
// packet from an unauthenticated peer would end a capture run.
//
// flamingo releases 386 and arm builds, so this is not hypothetical. On those
// platforms the affected listeners decline to start instead, and say why.
// Flamingo's own SMB, ADWS and NTLM code does its own bounds checking and is
// unaffected.
const upstreamType3Safe = bits.UintSize == 64

// errUpstream32Bit explains why a listener that depends on gopacket's relay
// package is unavailable on a 32-bit build.
func errUpstream32Bit(proto string) error {
	return fmt.Errorf(
		"%s is unavailable on %d-bit builds: its upstream NTLM parser can be "+
			"panicked by a crafted message where int is 32 bits, which would "+
			"terminate flamingo; run a 64-bit build to capture %s",
		proto, bits.UintSize, proto)
}
