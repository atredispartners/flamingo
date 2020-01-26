package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	syslog "github.com/RackSec/srslog"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	stdlog "log"

	"github.com/atredispartners/flamingo/pkg/flamingo"
	log "github.com/sirupsen/logrus"
)

var protocolCount = 0
var stdoutLogging = false

var cleanupHandlers = []func(){}

func startCapture(cmd *cobra.Command, args []string) {

	running := false
	state := new(sync.Mutex)

	fm := log.FieldMap{
		log.FieldKeyTime: "_etime",
		log.FieldKeyMsg:  "output",
	}

	// Configure the JSON formatter
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339, FieldMap: fm})
	log.SetOutput(os.Stdout)

	// Redirect the standard logger to logrus output (for ldap and other libraries)
	redirLog := log.New()
	redirLog.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339, FieldMap: fm})
	stdlog.SetOutput(redirLog.Writer())
	stdlog.SetFlags(0)

	// Set debug level if verbose is configured
	if params.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	if !params.Quiet {
		fmt.Fprintf(os.Stderr, "flamingo %s is waiting to feed...\n", Version)
	}

	// Bump the process file limit if possible
	flamingo.IncreaseFileLimit()

	done := false
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		state.Lock()
		defer state.Unlock()
		if !running {
			log.Printf("terminating early...")
			os.Exit(1)
		}
		done = true

	}()

	// Process CLI arguments
	protocols := make(map[string]bool)
	for _, pname := range strings.Split(params.Protocols, ",") {
		pname = strings.TrimSpace(pname)
		protocols[pname] = true
	}

	// Verify HTTP authentication mode
	switch params.HTTPAuthMode {
	case "ntlm", "basic":
		// OK
	case "":
		// Default to NTLM if empty
		params.HTTPAuthMode = "ntlm"
	default:
		// Bail out early
		log.Fatalf("invalid HTTP authentication mode specified: %s", params.HTTPAuthMode)
	}

	// Configure output actions
	rw := setupOutput(args)

	// Configure TLS certificates
	setupTLS()

	// Setup protocol listeners

	// SNMP
	if _, enabled := protocols["snmp"]; enabled {
		setupSNMP(rw)
	}

	// SSH
	if _, enabled := protocols["ssh"]; enabled {
		setupSSH(rw)
	}

	// LDAP/LDAPS
	if _, enabled := protocols["ldap"]; enabled {
		setupLDAP(rw)
		setupLDAPS(rw)
	}

	// HTTP/HTTPS
	if _, enabled := protocols["http"]; enabled {
		setupHTTP(rw)
		setupHTTPS(rw)
	}

	// DNS
	if _, enabled := protocols["dns"]; enabled {
		setupDNS(rw)
	}

	// FTP
	if _, enabled := protocols["ftp"]; enabled {
		setupFTP(rw)
	}

	// Make sure at least one capture is running
	if protocolCount == 0 {
		log.Fatalf("at least one protocol must be enabled")
	}

	state.Lock()
	running = true
	state.Unlock()

	// Main loop
	for {
		if done {
			log.Printf("shutting down...")

			// Clean up protocol handlers
			for _, handler := range cleanupHandlers {
				handler()
			}

			// Stop processing output
			rw.Done()

			// Clean up output writers
			for _, handler := range rw.OutputCleaners {
				handler()
			}
			break
		}
		time.Sleep(time.Second)
	}
}

func setupOutput(outputs []string) *flamingo.RecordWriter {
	stdoutLogging := false

	rw := flamingo.NewRecordWriter()

	// Default logs to standard output and flamingo.log
	if len(outputs) == 0 {
		outputs = []string{
			"stdout",
			"flamingo.log",
		}
	}

	if !params.Quiet {
		log.Infof("saving credentials to %s", strings.Join(outputs, ", "))
	}

	for _, output := range outputs {
		if (output == "-" || output == "stdout") && !stdoutLogging {
			rw.OutputWriters = append(rw.OutputWriters, stdoutWriter)
			stdoutLogging = true
			continue
		}

		if strings.HasPrefix(output, "http://") || strings.HasPrefix(output, "https://") {
			writer, cleaner, err := getWebhookWriter(output)
			if err != nil {
				log.Fatalf("failed to configure output %s: %s", output, err)
			}
			rw.OutputWriters = append(rw.OutputWriters, writer)
			if cleaner != nil {
				rw.OutputCleaners = append(rw.OutputCleaners, cleaner)
			}
			continue
		}

		if strings.HasPrefix(output, "syslog:") || output == "syslog" {
			writer, cleaner, err := getSyslogWriter(output)
			if err != nil {
				log.Fatalf("failed to configure output %s: %s", output, err)
			}
			rw.OutputWriters = append(rw.OutputWriters, writer)
			if cleaner != nil {
				rw.OutputCleaners = append(rw.OutputCleaners, cleaner)
			}
			continue
		}

		// Assume anything else is a file output
		writer, cleaner, err := getFileWriter(output)
		if err != nil {
			log.Fatalf("failed to configure output %s: %s", output, err)
		}
		rw.OutputWriters = append(rw.OutputWriters, writer)
		if cleaner != nil {
			rw.OutputCleaners = append(rw.OutputCleaners, cleaner)
		}
		continue
	}

	// Always log to standard output
	if !stdoutLogging {
		rw.OutputWriters = append(rw.OutputWriters, stdoutWriter)
	}

	return rw
}

func stdoutWriter(rec map[string]string) error {
	lf := log.Fields{}
	for k, v := range rec {
		if k == "_etime" {
			continue
		}
		lf[k] = v
	}

	rtype := rec["_type"]
	if rtype == "" {
		rtype = "credential"
	}

	switch rtype {
	case "credential":
		log.WithFields(lf).Warn(rtype)
	default:
		log.WithFields(lf).Info(rtype)
	}

	return nil
}

func getFileWriter(path string) (flamingo.OutputWriter, flamingo.OutputCleaner, error) {

	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return flamingo.OutputWriterNoOp, nil, err
	}

	return func(rec map[string]string) error {
		bytes, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		fmt.Fprintln(fd, string(bytes))
		return nil
	}, func() { fd.Close() }, nil
}

func getWebhookWriter(url string) (flamingo.OutputWriter, flamingo.OutputCleaner, error) {
	return func(rec map[string]string) error {
		bytes, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return sendWebhook(url, string(bytes))
	}, flamingo.OutputCleanerNoOp, nil
}

func getSyslogWriter(url string) (flamingo.OutputWriter, flamingo.OutputCleaner, error) {

	var syslogWriter *syslog.Writer
	var err error

	// Supported formats
	// - syslog - send to the default syslog output, typically a unix socket
	// - syslog:unix:/dev/log - send to a specific unix stream socket
	// - syslog:host - send to the specified host using udp and port 514
	// - syslog:host:port - send to the specified host using udp and the specified port
	// - syslog:udp:host - send to the specified host using udp and port 514
	// - syslog:udp:host:port - send to the specified host using udp and the specified port
	// - syslog:tcp:host - send to the specified host using tcp and port 514
	// - syslog:tcp:host:port - send to the specified host using tcp and the specified port
	// - syslog:tcp+tls:host - send to the specified host using tls over tcp and port 514
	// - syslog:tcp+tls:host:port - send to the specified host using tls over tcp and the specified port

	bits := strings.Split(url, ":")
	switch len(bits) {
	case 1:
		syslogWriter, err = syslog.Dial("", "", syslog.LOG_ALERT, "flamingo")
	case 2:
		syslogWriter, err = syslog.Dial("udp", fmt.Sprintf("%s:514", bits[1]), syslog.LOG_ALERT, "flamingo")
	case 3:
		switch bits[1] {
		case "unix":
			syslogWriter, err = syslog.Dial("", bits[2], syslog.LOG_ALERT, "flamingo")
		case "udp", "tcp", "tcp+tls":
			syslogWriter, err = syslog.Dial(bits[1], fmt.Sprintf("%s:514", bits[2]), syslog.LOG_ALERT, "flamingo")
		default:
			syslogWriter, err = syslog.Dial("udp", fmt.Sprintf("%s:%s", bits[1], bits[2]), syslog.LOG_ALERT, "flamingo")
		}

	case 4:
		switch bits[1] {
		case "unix":
			syslogWriter, err = syslog.Dial("", bits[2], syslog.LOG_ALERT, "flamingo")
		case "udp", "tcp", "tcp+tls":
			syslogWriter, err = syslog.Dial(bits[1], fmt.Sprintf("%s:%s", bits[2], bits[3]), syslog.LOG_ALERT, "flamingo")
		default:
			err = fmt.Errorf("unsupported syslog transport %s", bits[1])
		}
	default:
		err = fmt.Errorf("unsupported syslog destination %s", url)
	}

	if err != nil {
		return flamingo.OutputWriterNoOp, flamingo.OutputCleanerNoOp, err
	}

	err = syslogWriter.Debug("flamingo is starting up")
	if err != nil {
		return flamingo.OutputWriterNoOp, flamingo.OutputCleanerNoOp, err
	}

	return func(rec map[string]string) error {
		msg, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		rtype := rec["_type"]
		if rtype == "" {
			rtype = "credential"
		}

		switch rtype {
		case "credential":
			syslogWriter.Alert(string(msg))
		default:
			syslogWriter.Info(string(msg))
		}

		return nil
	}, func() { syslogWriter.Close() }, nil
}

func setupTLS() {
	tlsCertData := ""
	tlsKeyData := ""

	if params.TLSCertFile != "" {
		raw, err := ioutil.ReadFile(params.TLSCertFile)
		if err != nil {
			log.Fatalf("failed to read TLS certificate: %s", err)
		}
		tlsCertData = string(raw)
		tlsKeyData = tlsCertData

		if params.TLSKeyFile != "" {
			rawKey, err := ioutil.ReadFile(params.TLSKeyFile)
			if err != nil {
				log.Fatalf("failed to read TLS certificate: %s", err)
			}
			tlsKeyData = string(rawKey)
		}
	}

	if tlsCertData == "" || tlsKeyData == "" {
		generateTLSCertificate()
	}
}

func setupSSH(rw *flamingo.RecordWriter) {
	sshHostKey := ""
	if params.SSHHostKey != "" {
		data, err := ioutil.ReadFile(params.SSHHostKey)
		if err != nil {
			log.Fatalf("failed to read ssh host key %s: %s", params.SSHHostKey, err)
		}
		sshHostKey = string(data)
	}

	if params.SSHHostKey == "" {
		pkey, err := flamingo.SSHGenerateRSAKey(2048)
		if err != nil {
			log.Fatalf("failed to create ssh host key: %s", err)
		}
		sshHostKey = string(pkey)
	}

	// Create a listener for each port
	sshPorts, err := flamingo.CrackPorts(params.SSHPorts)
	if err != nil {
		log.Fatalf("failed to process ssh ports %s: %s", params.SSHPorts, err)
	}
	for _, port := range sshPorts {
		port := port
		sshConf := flamingo.NewConfSSH()
		sshConf.PrivateKey = sshHostKey
		sshConf.BindPort = uint16(port)
		sshConf.RecordWriter = rw
		if err := flamingo.SpawnSSH(sshConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start ssh server %s:%d: %s", sshConf.BindHost, sshConf.BindPort, err)
			} else {
				log.Errorf("failed to start ssh server %s:%d: %s", sshConf.BindHost, sshConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { sshConf.Shutdown() })
	}
}

func setupSNMP(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	snmpPorts, err := flamingo.CrackPorts(params.SNMPPorts)
	if err != nil {
		log.Fatalf("failed to process snmp ports %s: %s", params.SSHPorts, err)
	}

	for _, port := range snmpPorts {
		port := port
		snmpConf := flamingo.NewConfSNMP()
		snmpConf.BindPort = uint16(port)
		snmpConf.RecordWriter = rw
		if err := flamingo.SpawnSNMP(snmpConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start snmp server %s:%d: %s", snmpConf.BindHost, snmpConf.BindPort, err)
			} else {
				log.Errorf("failed to start snmb server %s:%d: %s", snmpConf.BindHost, snmpConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { snmpConf.Shutdown() })
	}
}

func setupLDAP(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	ldapPorts, err := flamingo.CrackPorts(params.LDAPPorts)
	if err != nil {
		log.Fatalf("failed to process ldap ports %s: %s", params.LDAPPorts, err)
	}

	for _, port := range ldapPorts {
		port := port
		ldapConf := flamingo.NewConfLDAP()
		ldapConf.BindPort = uint16(port)
		ldapConf.RecordWriter = rw
		if err := flamingo.SpawnLDAP(ldapConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start ldap server %s:%d: %s", ldapConf.BindHost, ldapConf.BindPort, err)
			} else {
				log.Errorf("failed to start ldap server %s:%d: %s", ldapConf.BindHost, ldapConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { ldapConf.Shutdown() })
	}
}

func setupLDAPS(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	ldapsPorts, err := flamingo.CrackPorts(params.LDAPSPorts)
	if err != nil {
		log.Fatalf("failed to process ldap ports %s: %s", params.LDAPSPorts, err)
	}

	for _, port := range ldapsPorts {
		port := port
		ldapConf := flamingo.NewConfLDAP()
		ldapConf.BindPort = uint16(port)
		ldapConf.RecordWriter = rw
		ldapConf.TLS = true
		ldapConf.TLSCert = params.TLSCertData
		ldapConf.TLSKey = params.TLSKeyData
		ldapConf.TLSName = params.TLSName
		if err := flamingo.SpawnLDAP(ldapConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start ldaps server %s:%d: %q", ldapConf.BindHost, ldapConf.BindPort, err)
			} else {
				log.Errorf("failed to start ldaps server %s:%d: %q", ldapConf.BindHost, ldapConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { ldapConf.Shutdown() })
	}
}

func setupHTTP(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	httpPorts, err := flamingo.CrackPorts(params.HTTPPorts)
	if err != nil {
		log.Fatalf("failed to process ldap ports %s: %s", params.HTTPPorts, err)
	}

	for _, port := range httpPorts {
		port := port
		httpConf := flamingo.NewConfHTTP()
		httpConf.BindPort = uint16(port)
		httpConf.RecordWriter = rw
		httpConf.BasicRealm = params.HTTPBasicRealm
		httpConf.AuthMode = params.HTTPAuthMode
		if err := flamingo.SpawnHTTP(httpConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start ldaps server %s:%d: %q", httpConf.BindHost, httpConf.BindPort, err)
			} else {
				log.Errorf("failed to start ldaps server %s:%d: %q", httpConf.BindHost, httpConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { httpConf.Shutdown() })
	}
}

func setupHTTPS(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	httpsPorts, err := flamingo.CrackPorts(params.HTTPSPorts)
	if err != nil {
		log.Fatalf("failed to process ldap ports %s: %s", params.HTTPSPorts, err)
	}

	for _, port := range httpsPorts {
		port := port
		httpConf := flamingo.NewConfHTTP()
		httpConf.BindPort = uint16(port)
		httpConf.RecordWriter = rw
		httpConf.BasicRealm = params.HTTPBasicRealm
		httpConf.TLS = true
		httpConf.TLSCert = params.TLSCertData
		httpConf.TLSKey = params.TLSKeyData
		httpConf.TLSName = params.TLSName
		httpConf.AuthMode = params.HTTPAuthMode
		if err := flamingo.SpawnHTTP(httpConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start ldaps server %s:%d: %q", httpConf.BindHost, httpConf.BindPort, err)
			} else {
				log.Errorf("failed to start ldaps server %s:%d: %q", httpConf.BindHost, httpConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { httpConf.Shutdown() })
	}
}

func setupDNS(rw *flamingo.RecordWriter) {

	// Create a listener for each port
	dnsPorts, err := flamingo.CrackPorts(params.DNSPorts)
	if err != nil {
		log.Fatal("failed to process dns ports %s: %s", params.DNSPorts, err)
	}

	for _, port := range dnsPorts {
		dnsConf := flamingo.NewConfDNS()
		dnsConf.BindPort = uint16(port)
		dnsConf.RecordWriter = rw
		dnsConf.ResolveToIP = params.DNSResolveToIP
		if err := flamingo.SpawnDNS(dnsConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start dns server %s:%d: %q", dnsConf.BindHost, dnsConf.BindPort, err)
			} else {
				log.Errorf("failed to start dns server %s:%d: %q", dnsConf.BindHost, dnsConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { dnsConf.Shutdown() })
	}
}

func setupFTP(rw *flamingo.RecordWriter) {

	// Create a listner for each port
	ftpPorts, err := flamingo.CrackPorts(params.FTPPorts)
	if err != nil {
		log.Fatal("failed to process ftp ports %s: %s", params.FTPPorts, err)
	}

	for _, port := range ftpPorts {
		ftpConf := flamingo.NewConfFTP()
		ftpConf.BindPort = uint16(port)
		ftpConf.RecordWriter = rw
		if err := flamingo.SpawnFTP(ftpConf); err != nil {
			if params.DontIgnoreFailures {
				log.Fatalf("failed to start dns server %s:%d: %q", ftpConf.BindHost, ftpConf.BindPort, err)
			} else {
				log.Errorf("failed to start dns server %s:%d: %q", ftpConf.BindHost, ftpConf.BindPort, err)
			}
			continue
		}
		protocolCount++
		cleanupHandlers = append(cleanupHandlers, func() { ftpConf.Shutdown() })
	}
}

func sendWebhook(url string, msg string) error {
	body, _ := json.Marshal(map[string]string{"text": msg})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", fmt.Sprintf("flamingo/%s", Version))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * time.Duration(15)}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("bad response: %d", resp.StatusCode)
	}

	return nil
}
