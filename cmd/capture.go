package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/atredispartners/flamingo/pkg/flamingo"
	log "github.com/sirupsen/logrus"
)

var protocolCount = 0
var stdoutLogging = false

var cleanupHandlers = []func(){}

func startCapture(cmd *cobra.Command, args []string) {

	fm := log.FieldMap{
		log.FieldKeyTime: "_etime",
		log.FieldKeyMsg:  "output",
	}

	// Configure the JSON formatter
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339, FieldMap: fm})

	// Set debug level if verbose is configured
	if params.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	done := false
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done = true
	}()

	// Process CLI arguments
	protocols := make(map[string]bool)
	for _, pname := range strings.Split(params.Protocols, ",") {
		pname = strings.TrimSpace(pname)
		protocols[pname] = true
	}

	// Configure output actions
	rw := setupOutput(args)

	// Setup protocol listeners

	// SNMP
	if _, enabled := protocols["snmp"]; enabled {
		setupSNMP(rw)
	}

	// SSH
	if _, enabled := protocols["ssh"]; enabled {
		setupSSH(rw)
	}

	// Make sure at least one capture is running
	if protocolCount == 0 {
		log.Fatalf("at least one protocol must be enabled")
	}

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
	if len(outputs) == 0 {
		rw.OutputWriters = append(rw.OutputWriters, stdoutWriter)
		stdoutLogging = true
		return rw
	}

	for _, output := range outputs {
		if output == "-" && !stdoutLogging {
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

		// Assume anything else is a file output
		writer, cleaner, err := getFileWriter(output)
		if err != nil {
			log.Fatalf("failed to configure output %s: %s", output, err)
		}
		rw.OutputWriters = append(rw.OutputWriters, writer)
		if cleaner != nil {
			rw.OutputCleaners = append(rw.OutputCleaners, cleaner)
		}
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

	log.WithFields(lf).Info("credential")
	return nil
}

func getFileWriter(path string) (flamingo.OutputWriter, flamingo.OutputCleaner, error) {
	fd, err := os.Create(path)
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

func setupSSH(rw *flamingo.RecordWriter) {

	sshHostKey := ""
	if params.SSHHostKey != "" {
		data, err := ioutil.ReadFile(params.SSHHostKey)
		if err != nil {
			log.Fatalf("failed to read ssh host key %s: %s", params.SSHHostKey, err)
		}
		sshHostKey = string(data)
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
			log.Fatalf("failed to start ssh server: %q", err)
		}
		cleanupHandlers = append(cleanupHandlers, func() { sshConf.Shutdown() })
	}

	protocolCount++
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
			log.Fatalf("failed to start snmp server: %q", err)
		}
		cleanupHandlers = append(cleanupHandlers, func() { snmpConf.Shutdown() })
	}

	protocolCount++
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
