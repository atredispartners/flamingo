package flamingo

import (
	"fmt"
	"strconv"
	"strings"
)

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

	bits := strings.Split(pspec, ",")
	for _, bit := range bits {

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
