package flamingo

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// VNCChallenge is the fixed 16-byte server challenge presented to every
// client. A static challenge (rather than a random one) means captured
// responses can be cracked offline with precomputed material, the same
// trade flamingo already makes with its fixed NTLM challenge. The bytes
// here are arbitrary but constant.
var VNCChallenge = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

// RFB security types
const (
	vncSecTypeInvalid = 0
	vncSecTypeNone    = 1
	vncSecTypeVNCAuth = 2
)

// ConfVNC holds the configuration for a VNC (RFB) capture server.
type ConfVNC struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfVNC creates a default configuration for the VNC capture server.
func NewConfVNC() *ConfVNC {
	return &ConfVNC{
		BindPort: 5900,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfVNC) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfVNC) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnVNC creates a new VNC capture server.
func SpawnVNC(c *ConfVNC) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	log.Debugf("vnc is listening on %s:%d", c.BindHost, c.BindPort)
	c.listener = listener
	go vncStart(c)
	return nil
}

func vncStart(c *ConfVNC) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go vncHandleConnection(c, conn)
	}
}

// vncHandleConnection walks a connecting client through the RFB handshake
// far enough to capture a VNC Authentication (security type 2) response.
//
// The RFB flow, from the server side:
//  1. Server sends its ProtocolVersion ("RFB 003.008\n").
//  2. Client replies with the version it will speak.
//  3. Server advertises VNC Authentication as the only security type.
//     RFB 3.7+ sends a count-prefixed list; RFB 3.3 sends a bare uint32.
//  4. Server sends the 16-byte challenge.
//  5. Client sends the 16-byte DES response. That challenge/response pair
//     is the crackable artifact.
//  6. Server returns a SecurityResult of failed and closes.
func vncHandleConnection(c *ConfVNC, conn net.Conn) {
	defer conn.Close()

	// Don't let a silent client tie up the handler forever.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: advertise RFB 3.8.
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}

	// Step 2: read the client's 12-byte ProtocolVersion ("RFB 003.00x\n").
	clientVersion := make([]byte, 12)
	if _, err := io.ReadFull(conn, clientVersion); err != nil {
		return
	}
	minor := vncParseMinor(clientVersion)

	// Step 3: advertise VNC Authentication. The wire format depends on the
	// version the client offered.
	if minor >= 7 {
		// uint8 count, then that many uint8 security types.
		if _, err := conn.Write([]byte{1, vncSecTypeVNCAuth}); err != nil {
			return
		}
		// Client replies with the single security type it selected.
		sel := make([]byte, 1)
		if _, err := io.ReadFull(conn, sel); err != nil {
			return
		}
		if sel[0] != vncSecTypeVNCAuth {
			return
		}
	} else {
		// RFB 3.3: server dictates the security type as a uint32.
		if _, err := conn.Write([]byte{0, 0, 0, vncSecTypeVNCAuth}); err != nil {
			return
		}
	}

	// Step 4: send the fixed challenge.
	if _, err := conn.Write(VNCChallenge); err != nil {
		return
	}

	// Step 5: read the 16-byte response.
	response := make([]byte, 16)
	if _, err := io.ReadFull(conn, response); err != nil {
		return
	}

	// Step 6: tell the client authentication failed and close. We never had
	// a real session to offer; a failure result is both honest to the
	// protocol and discourages the client from proceeding further.
	if minor >= 7 {
		conn.Write([]byte{0, 0, 0, 1, 0, 0, 0, 21})
		conn.Write([]byte("Authentication failed"))
	} else {
		conn.Write([]byte{0, 0, 0, 1})
	}

	challengeHex := hex.EncodeToString(VNCChallenge)
	responseHex := hex.EncodeToString(response)

	c.RecordWriter.Record(
		"credential",
		"vnc",
		conn.RemoteAddr().String(),
		map[string]string{
			"_server":   fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
			"challenge": challengeHex,
			"response":  responseHex,
			// John the Ripper "vnc" format: $vnc$*challenge*response
			"john": fmt.Sprintf("$vnc$*%s*%s", challengeHex, responseHex),
			// hashcat mode 14000 wants response:challenge, first 8 bytes each
			"hashcat": fmt.Sprintf("%s:%s", responseHex[:16], challengeHex[:16]),
			"method":  "VNC",
		},
	)
}

// vncParseMinor extracts the minor version from a 12-byte RFB
// ProtocolVersion string such as "RFB 003.008\n". It returns 3 as a safe
// default when the string can't be parsed, which selects the most
// permissive (RFB 3.3) handshake.
func vncParseMinor(version []byte) int {
	// Expected layout: "RFB 003.008\n", minor digits at offset 8..10.
	if len(version) < 11 || string(version[:4]) != "RFB " {
		return 3
	}
	minor := 0
	for i := 8; i < 11; i++ {
		d := version[i]
		if d < '0' || d > '9' {
			return 3
		}
		minor = minor*10 + int(d-'0')
	}
	return minor
}
