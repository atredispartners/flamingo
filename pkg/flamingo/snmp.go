package flamingo

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/gosnmp/gosnmp"
	log "github.com/sirupsen/logrus"
)

// ConfSNMP describes the options for a snmp service
type ConfSNMP struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.PacketConn
	m            sync.Mutex
}

// IsShutdown checks to see if the service is shutting down
func (c *ConfSNMP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfSNMP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	c.listener.Close()
}

// NewConfSNMP creates a default configuration for the SNMP capture server
func NewConfSNMP() *ConfSNMP {
	return &ConfSNMP{
		BindPort: 161,
		BindHost: "[::]",
	}
}

var snmpDecoders = []*gosnmp.GoSNMP{
	&gosnmp.GoSNMP{Version: gosnmp.Version2c},
	// TODO: Do something with SNMP v3 requests
	// &gosnmp.GoSNMP{Version: gosnmp.Version3},
}

// SpawnSNMP starts a logging SNMP server
func SpawnSNMP(c *ConfSNMP) error {
	// Create the UDP listener
	listener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d (%s)", c.BindHost, c.BindPort, err)
	}

	udpSocket, ok := listener.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("failed to listen on %s:%d (bad socket)", c.BindHost, c.BindPort)
	}

	// Track the socket
	c.listener = udpSocket

	// Start the snmp handler
	go snmpStart(c)

	return nil
}

func snmpStart(c *ConfSNMP) {
	log.Debugf("snmp is listening on %s:%d", c.BindHost, c.BindPort)

	buff := make([]byte, 4096)
	for {
		if c.IsShutdown() {
			log.Debugf("snmp server on %s:%d is shutting down", c.BindHost, c.BindPort)
			break
		}

		rlen, raddr, rerr := c.listener.ReadFrom(buff)
		if rerr != nil {
			continue
		}

		data := buff[0:rlen]
		snmpProcess(c, raddr, data)
	}
}

func snmpProcess(c *ConfSNMP, raddr net.Addr, data []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("snmp decoder panic with data %s: %q", hex.EncodeToString(data), r)
		}
	}()
	snmpProcessData(c, raddr, data)
}

func snmpProcessData(c *ConfSNMP, raddr net.Addr, data []byte) {
	for _, decoder := range snmpDecoders {
		res, err := decoder.SnmpDecodePacket(data)
		if err != nil {
			continue
		}

		if res.Community == "" {
			continue
		}

		// TODO
		// - Handle SNMP v3
		// - Handle SNMP Traps

		c.RecordWriter.Record("credential", "snmp", raddr.String(), map[string]string{
			"community": res.Community,
			"version":   res.Version.String(),
			"_server":   fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		})
	}
}
