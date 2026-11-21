package ber

import "testing"

// TestDecodeZeroLengthElement covers BER elements whose value is empty. A TLV
// is complete at two bytes, and because decodePacket recurses, rejecting those
// failed the entire enclosing message.
func TestDecodeZeroLengthElement(t *testing.T) {
	t.Run("bare", func(t *testing.T) {
		p, rest, err := decodePacket([]byte{0x04, 0x00})
		if err != nil {
			t.Fatalf("zero-length OCTET STRING rejected: %v", err)
		}
		if len(p.ByteValue) != 0 {
			t.Errorf("value = %q, want empty", p.ByteValue)
		}
		if len(rest) != 0 {
			t.Errorf("rest = %d bytes, want 0", len(rest))
		}
	})

	// An LDAP simple bind carrying an empty password: the final element is a
	// zero-length TLV. Flamingo must still see the username.
	t.Run("ldap bind with empty password", func(t *testing.T) {
		pkt := []byte{
			0x30, 0x0e,
			0x02, 0x01, 0x01, // messageID 1
			0x60, 0x09, // BindRequest
			0x02, 0x01, 0x03, // version 3
			0x04, 0x02, 'h', 'i', // name "hi"
			0x80, 0x00, // simple auth, empty password
		}
		p, _, err := decodePacket(pkt)
		if err != nil {
			t.Fatalf("bind with an empty password rejected: %v", err)
		}
		if len(p.Children) != 2 {
			t.Fatalf("top-level children = %d, want 2", len(p.Children))
		}
		bind := p.Children[1]
		if len(bind.Children) != 3 {
			t.Fatalf("BindRequest children = %d, want 3 (version, name, auth)", len(bind.Children))
		}
		if got := string(bind.Children[1].ByteValue); got != "hi" {
			t.Errorf("bind name = %q, want %q", got, "hi")
		}
		if n := len(bind.Children[2].ByteValue); n != 0 {
			t.Errorf("password length = %d, want 0", n)
		}
	})

	// A single byte is still too short.
	t.Run("one byte", func(t *testing.T) {
		if _, _, err := decodePacket([]byte{0x04}); err == nil {
			t.Error("a one-byte packet was accepted")
		}
	})
}
