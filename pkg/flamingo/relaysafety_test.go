package flamingo

import (
	"math/bits"
	"strings"
	"testing"
)

// TestUpstreamType3Safe pins the platform rule. The listeners built on
// gopacket's relay package must refuse to start where int is 32 bits, because
// a crafted NTLM AUTHENTICATE panics upstream's parser on a goroutine we
// cannot recover, taking the whole process with it.
func TestUpstreamType3Safe(t *testing.T) {
	if got, want := upstreamType3Safe, bits.UintSize == 64; got != want {
		t.Fatalf("upstreamType3Safe = %v on a %d-bit build, want %v", got, bits.UintSize, want)
	}

	err := errUpstream32Bit("msrpc")
	if err == nil {
		t.Fatal("errUpstream32Bit returned nil")
	}
	for _, want := range []string{"msrpc", "64-bit build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestUpstreamGuardedSpawns checks each affected listener consults the guard.
// On a 64-bit build they must start normally; on 32-bit they must decline with
// the explanatory error rather than listening.
func TestUpstreamGuardedSpawns(t *testing.T) {
	cases := []struct {
		proto string
		spawn func() (func(), error)
	}{
		{"msrpc", func() (func(), error) {
			c := NewConfMSRPC()
			c.BindHost, c.BindPort, c.RecordWriter = "127.0.0.1", 0, NewRecordWriter()
			return c.Shutdown, SpawnMSRPC(c)
		}},
		{"winrm", func() (func(), error) {
			c := NewConfWinRM()
			c.BindHost, c.BindPort, c.RecordWriter = "127.0.0.1", 0, NewRecordWriter()
			return c.Shutdown, SpawnWinRM(c)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			shutdown, err := tc.spawn()
			if shutdown != nil {
				defer shutdown()
			}
			if upstreamType3Safe {
				if err != nil {
					t.Fatalf("%s refused to start on a 64-bit build: %s", tc.proto, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s started on a 32-bit build; it must decline", tc.proto)
			}
			if !strings.Contains(err.Error(), "64-bit build") {
				t.Errorf("error %q does not explain the platform limit", err)
			}
		})
	}
}
