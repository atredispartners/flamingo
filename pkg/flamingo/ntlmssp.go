package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

func ntlmsspExtractFieldsFromBlob(blob []byte) map[string]string {
	var err error
	res := make(map[string]string)

	ntlmsspOffset := bytes.Index(blob, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, 0x02, 0x00, 0x00, 0x00})
	if ntlmsspOffset < 0 {
		return res
	}

	data := blob[ntlmsspOffset:]

	// Basic sanity check
	if len(data) < (12 + 6 + 12 + 8 + 6 + 8) {
		return res
	}

	idx := 12

	targetName, idx, err := ntlmsspExtractOffset(data, idx)
	if err != nil {
		return res
	}

	// Negotiate Flags
	negotiateFlags := binary.LittleEndian.Uint32(data[idx:])
	res["flags"] = fmt.Sprintf("0x%.8x", negotiateFlags)
	idx += 4

	// NTLM Server Challenge
	idx += 8

	// Reserved
	idx += 8

	// Target Info
	targetInfo, idx, err := ntlmsspExtractOffset(data, idx)
	if err != nil {
		return res
	}

	// Version
	versionMajor := uint8(data[idx])
	idx++

	versionMinor := uint8(data[idx])
	idx++

	versionBuild := binary.LittleEndian.Uint16(data[idx:])
	idx += 2

	ntlmRevision := binary.BigEndian.Uint32(data[idx:])

	// macOS reverses the endian order of this field for some reason
	if ntlmRevision == 251658240 {
		ntlmRevision = binary.LittleEndian.Uint32(data[idx:])
	}

	res["version"] = fmt.Sprintf("%d.%d.%d", versionMajor, versionMinor, versionBuild)
	res["revision"] = fmt.Sprintf("%d", ntlmRevision)
	res["target_name"] = ntlmsspTrimName(string(targetName))

	idx = 0
	for {
		if idx+4 > len(targetInfo) {
			break
		}

		attrType := binary.LittleEndian.Uint16(targetInfo[idx:])
		idx += 2

		// End of List
		if attrType == 0 {
			break
		}

		attrLen := binary.LittleEndian.Uint16(targetInfo[idx:])
		idx += 2

		if idx+int(attrLen) > len(targetInfo) {
			// Too short
			break
		}

		attrVal := targetInfo[idx : idx+int(attrLen)]
		idx += int(attrLen)

		switch attrType {
		case 1:
			res["nb_computer"] = ntlmsspTrimName(string(attrVal))
		case 2:
			res["nb_domain"] = ntlmsspTrimName(string(attrVal))
		case 3:
			res["dns_computer"] = ntlmsspTrimName(string(attrVal))
		case 4:
			res["dns_domain"] = ntlmsspTrimName(string(attrVal))
		case 7:
			ts := binary.LittleEndian.Uint64(attrVal[:])
			res["timestamp"] = fmt.Sprintf("0x%.16x", ts)
		}

		// End of List
		if attrType == 0 {
			break
		}
	}
	return res
}

func ntlmsspExtractOffset(blob []byte, idx int) ([]byte, int, error) {
	res := []byte{}

	if len(blob) < (idx + 6) {
		return res, idx, fmt.Errorf("data truncated")
	}

	len1 := binary.LittleEndian.Uint16(blob[idx:])
	idx += 2

	// len2 := binary.LittleEndian.Uint16(blob[idx:])
	idx += 2

	off := binary.LittleEndian.Uint32(blob[idx:])
	idx += 4

	// Allow zero length values
	if len1 == 0 {
		return res, idx, nil
	}

	if len(blob) < int(off+uint32(len1)) {
		return res, idx, fmt.Errorf("data value truncated")
	}

	res = append(res, blob[off:off+uint32(len1)]...)
	return res, idx, nil
}

func ntlmsspTrimName(name string) string {
	return strings.TrimSpace(strings.Replace(name, "\x00", "", -1))
}
