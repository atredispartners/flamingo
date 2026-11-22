package cmd

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/atredispartners/flamingo/pkg/flamingo"
	log "github.com/sirupsen/logrus"
)

// relayParameters holds the flags for NTLM relaying. Relaying is the one
// behaviour here that authenticates to a third party as the victim, so it is
// kept in its own file and is inert unless --relay-targets names somewhere.
type relayParameters struct {
	Targets      string
	Attacks      string
	OneShot      bool
	RandomTarget bool
	Timeout      time.Duration
}

var relayParams = &relayParameters{}

func init() {
	rootCmd.Flags().StringVarP(&relayParams.Targets, "relay-targets", "", "",
		"Relay captured NTLM authentication to these targets, e.g. smb://10.0.0.5,ldaps://dc01. "+
			"Empty disables relaying entirely. Authorized engagements only")
	rootCmd.Flags().StringVarP(&relayParams.Attacks, "relay-attack", "", "",
		fmt.Sprintf("Run these modules against a successfully relayed session (%s). "+
			"Empty, the default, authenticates and reports only", strings.Join(flamingo.RelayAttackNames(), ", ")))
	rootCmd.Flags().BoolVarP(&relayParams.OneShot, "relay-one-shot", "", false,
		"Stop relaying to a target once it has accepted a session")
	rootCmd.Flags().BoolVarP(&relayParams.RandomTarget, "relay-random-target", "", false,
		"Pick relay targets at random rather than round-robin")
	rootCmd.Flags().DurationVarP(&relayParams.Timeout, "relay-timeout", "", 0,
		"Per-call timeout when talking to a relay target (default 10s)")
}

// listenPorts collects every port flamingo was asked to listen on, so a relay
// target pointing back at one of our own listeners can be refused before any
// victim is redirected into a loop.
func listenPorts() []uint16 {
	var ports []uint16
	v := reflect.ValueOf(*params)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if !strings.HasSuffix(t.Field(i).Name, "Ports") || v.Field(i).Kind() != reflect.String {
			continue
		}
		spec := v.Field(i).String()
		if spec == "" {
			continue
		}
		cracked, err := flamingo.CrackPorts(spec)
		if err != nil {
			continue
		}
		for _, p := range cracked {
			ports = append(ports, uint16(p))
		}
	}
	return ports
}

// setupRelay builds the relay responder. It returns nil when no targets are
// configured, which leaves every listener capture-only.
func setupRelay(rw *flamingo.RecordWriter) flamingo.NTLMResponder {
	if strings.TrimSpace(relayParams.Targets) == "" {
		if strings.TrimSpace(relayParams.Attacks) != "" {
			log.Fatalf("--relay-attack needs --relay-targets: there is nothing to attack without a target")
		}
		return nil
	}

	policy := flamingo.RelayPolicyRoundRobin
	if relayParams.RandomTarget {
		policy = flamingo.RelayPolicyRandom
	}

	conf, err := flamingo.NewRelayConfig(flamingo.RelayOptions{
		Targets:      splitList(relayParams.Targets),
		Attacks:      splitList(relayParams.Attacks),
		Policy:       policy,
		OneShot:      relayParams.OneShot,
		ListenPorts:  listenPorts(),
		Timeout:      relayParams.Timeout,
		RecordWriter: rw,
	})
	if err != nil {
		log.Fatalf("invalid relay configuration: %s", err)
	}
	if conf == nil {
		return nil
	}

	if !params.Quiet {
		fmt.Fprintln(os.Stderr, conf.Banner())
	}
	return flamingo.NewRelayResponder(conf)
}

// splitList turns a comma-separated flag value into a trimmed list.
func splitList(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
