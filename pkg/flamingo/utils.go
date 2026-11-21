package flamingo

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// utf16String decodes UTF-16LE, dropping trailing NULs and an odd trailing
// byte.
func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// utf16Bytes encodes s as UTF-16LE.
func utf16Bytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// winFiletime converts t to a Windows FILETIME: 100-nanosecond intervals
// since 1601-01-01 UTC.
func winFiletime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

// ValidPort determines if a port number is valid
func ValidPort(pnum int) bool {
	if pnum < 0 || pnum > 65535 {
		return false
	}
	return true
}

// CrackPorts turns a comma-delimited port list into an array
func CrackPorts(pspec string) ([]int, error) {
	results := []int{}

	// Use a map to dedup and shuffle ports
	ports := make(map[int]bool)

	bits := strings.SplitSeq(pspec, ",")
	for bit := range bits {

		// Split based on dash
		prange := strings.Split(bit, "-")

		// No port range
		if len(prange) == 1 {
			pnum, err := strconv.Atoi(bit)
			if err != nil || !ValidPort(pnum) {
				return results, fmt.Errorf("invalid port %s", bit)
			}
			// Record the valid port
			ports[pnum] = true
			continue
		}

		if len(prange) != 2 {
			return results, fmt.Errorf("invalid port range %s (%d)", prange, len(prange))
		}

		pstart, err := strconv.Atoi(prange[0])
		if err != nil || !ValidPort(pstart) {
			return results, fmt.Errorf("invalid start port %d", pstart)
		}

		pstop, err := strconv.Atoi(prange[1])
		if err != nil || !ValidPort(pstop) {
			return results, fmt.Errorf("invalid stop port %d", pstop)
		}

		if pstart > pstop {
			return results, fmt.Errorf("invalid port range %d-%d", pstart, pstop)
		}

		for pnum := pstart; pnum <= pstop; pnum++ {
			ports[pnum] = true
		}
	}

	// Create the results from the map
	for port := range ports {
		results = append(results, port)
	}
	return results, nil
}
