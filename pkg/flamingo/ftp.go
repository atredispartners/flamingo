package flamingo

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

// ConfFTP holds information for a FTP server.
type ConfFTP struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfFTP creates a default configuration for the FTP capture server.
func NewConfFTP() *ConfFTP {
	return &ConfFTP{
		BindPort: 21,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfFTP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down
func (c *ConfFTP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	c.listener.Close()
}

// SpawnFTP creates a new FTP capture server.
func SpawnFTP(c *ConfFTP) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.BindHost, c.BindPort))
	if err != nil {
		return err
	}
	c.listener = listener
	go ftpStart(c)
	return nil
}

func ftpStart(c *ConfFTP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go ftpHandleConnection(c, conn)
	}
}

func ftpCreateMessage(code int, msg string) string {
	return fmt.Sprintf("%d %s\r\n", code, msg)
}

func ftpHandleConnection(c *ConfFTP, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writer.WriteString(ftpCreateMessage(220, "Welcome to FTP server."))
	writer.Flush()
	var (
		username string
		password string
	)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println(err)

			return
		}
		parts := strings.SplitN(strings.Trim(line, "\r\n"), " ", 2)
		if len(parts) < 2 {
			return
		}
		command := parts[0]
		msg := parts[1]
		switch command {
		case "USER":
			username = msg
			writer.WriteString(ftpCreateMessage(331, "Username ok, password required"))
			writer.Flush()
		case "PASS":
			password = msg
			writer.WriteString(ftpCreateMessage(230, "Password ok, continue"))
			writer.Flush()
		default:
			writer.WriteString(ftpCreateMessage(500, "Command not found"))
			writer.Flush()
			break
		}
		if username != "" && password != "" {
			c.RecordWriter.Record(
				"credential",
				"ftp",
				conn.RemoteAddr().String(),
				map[string]string{
					"username": username,
					"password": password,
					"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
				},
			)
			return
		}
	}

}
