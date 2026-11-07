package flamingo

import (
	"encoding/binary"
	"errors"
	"io"
)

// rdpCredSSPVersion is the highest TSRequest version the server speaks.
const rdpCredSSPVersion = 6

// rdpStatusLogonFailure is the NTSTATUS returned in the final TSRequest.
const rdpStatusLogonFailure = 0xC000006D

// rdpTSRequest is a decoded MS-CSSP TSRequest.
type rdpTSRequest struct {
	version    uint32
	tokens     [][]byte
	authInfo   []byte
	pubKeyAuth []byte
	nonce      []byte
	errorCode  uint32
	hasError   bool
}

// rdpParseTSRequest decodes a DER TSRequest.
func rdpParseTSRequest(b []byte) (*rdpTSRequest, error) {
	tag, seq, _, ok := rdpDERNext(b)
	if !ok || tag != 0x30 {
		return nil, errors.New("not a TSRequest")
	}
	r := &rdpTSRequest{}
	for i := 0; i < 8 && len(seq) > 0; i++ {
		tag, val, rest, ok := rdpDERNext(seq)
		if !ok {
			return nil, errors.New("bad TSRequest field")
		}
		seq = rest
		inner, ival, _, iok := rdpDERNext(val)
		switch tag {
		case 0xa0:
			if !iok || inner != 0x02 {
				return nil, errors.New("bad TSRequest version")
			}
			r.version, _ = rdpDERUint(ival)
		case 0xa1:
			if !iok || inner != 0x30 {
				return nil, errors.New("bad NegoData")
			}
			for j := 0; j < 4 && len(ival) > 0; j++ {
				t2, item, rest2, ok := rdpDERNext(ival)
				if !ok || t2 != 0x30 {
					break
				}
				ival = rest2
				if t3, ctx, _, ok := rdpDERNext(item); ok && t3 == 0xa0 {
					if t4, tok, _, ok := rdpDERNext(ctx); ok && t4 == 0x04 {
						r.tokens = append(r.tokens, tok)
					}
				}
			}
		case 0xa2:
			if iok && inner == 0x04 {
				r.authInfo = ival
			}
		case 0xa3:
			if iok && inner == 0x04 {
				r.pubKeyAuth = ival
			}
		case 0xa4:
			if iok && inner == 0x02 {
				r.errorCode, r.hasError = rdpDERUint(ival)
			}
		case 0xa5:
			if iok && inner == 0x04 {
				r.nonce = ival
			}
		}
	}
	return r, nil
}

// rdpEncodeTSRequest builds a TSRequest carrying a nego token and/or an
// error code.
func rdpEncodeTSRequest(version uint32, token []byte, errorCode *uint32) []byte {
	body := rdpDERWrap(0xa0, rdpDERInt(version))
	if token != nil {
		nego := rdpDERWrap(0x30, rdpDERWrap(0x30, rdpDERWrap(0xa0, rdpDERWrap(0x04, token))))
		body = append(body, rdpDERWrap(0xa1, nego)...)
	}
	if errorCode != nil {
		body = append(body, rdpDERWrap(0xa4, rdpDERInt(*errorCode))...)
	}
	return rdpDERWrap(0x30, body)
}

// rdpDERNext splits one BER/DER TLV with a single-byte tag off b.
func rdpDERNext(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	n, hdr, ok := rdpBERLen(b[1:])
	if !ok || n > len(b)-1-hdr {
		return 0, nil, nil, false
	}
	i := 1 + hdr
	return b[0], b[i : i+n], b[i+n:], true
}

// rdpBERLen decodes a BER length at the start of b, returning the length
// and the number of bytes it occupied.
func rdpBERLen(b []byte) (n, hdr int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	n = int(b[0])
	if n&0x80 == 0 {
		return n, 1, true
	}
	k := n & 0x7f
	if k == 0 || k > 3 || len(b) < 1+k {
		return 0, 0, false
	}
	n = 0
	for j := 0; j < k; j++ {
		n = n<<8 | int(b[1+j])
	}
	return n, 1 + k, true
}

// rdpBERLenBytes encodes a BER length.
func rdpBERLenBytes(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// rdpDERWrap builds one TLV.
func rdpDERWrap(tag byte, data []byte) []byte {
	out := append([]byte{tag}, rdpBERLenBytes(len(data))...)
	return append(out, data...)
}

// rdpDERInt encodes a non-negative INTEGER.
func rdpDERInt(v uint32) []byte {
	b := binary.BigEndian.AppendUint32(nil, v)
	for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return rdpDERWrap(0x02, b)
}

// rdpDERUint decodes an INTEGER of at most five bytes into a uint32.
func rdpDERUint(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 5 || (len(b) == 5 && b[0] != 0) {
		return 0, false
	}
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	return v, true
}

// rdpReadDER reads one complete TLV from r, capped at rdpMaxDER bytes.
func rdpReadDER(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msg := hdr[:]
	n := int(hdr[1])
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 2 {
			return nil, errors.New("bad DER length")
		}
		ext := make([]byte, k)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		msg = append(msg, ext...)
		n = 0
		for _, x := range ext {
			n = n<<8 | int(x)
		}
	}
	if n > rdpMaxDER {
		return nil, errors.New("DER message too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(msg, body...), nil
}
