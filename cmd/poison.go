package cmd

import (
	"github.com/atredispartners/flamingo/pkg/flamingo"
	log "github.com/sirupsen/logrus"
)

// poisonParameters holds the flags for the name-poisoning listeners (LLMNR,
// NBT-NS, mDNS). They live here rather than in flamingoParameters so the
// poisoner wiring stays self-contained.
type poisonParameters struct {
	LLMNRPorts string
	NBTNSPorts string
	MDNSPorts  string

	SpoofIPv4  string
	SpoofIPv6  string
	AnswerName string
	TTL        int

	RespondTo         string
	DontRespondTo     string
	RespondToName     string
	DontRespondToName string
	DontRespondToTLD  string
	Analyze           bool
}

var poisonParams = &poisonParameters{}

func init() {
	// Name poisoning is active, not passive: these listeners make hosts
	// connect to flamingo, so they are opt-in and OFF by default. Enable them
	// explicitly and only inside an authorized engagement scope, e.g.
	//   flamingo --protocols llmnr,nbtns,mdns,smb
	rootCmd.Flags().StringVarP(&poisonParams.LLMNRPorts, "llmnr-ports", "", "5355", "The list of UDP ports to listen on for LLMNR poisoning (opt-in)")
	rootCmd.Flags().StringVarP(&poisonParams.NBTNSPorts, "nbtns-ports", "", "137", "The list of UDP ports to listen on for NBT-NS poisoning (opt-in)")
	rootCmd.Flags().StringVarP(&poisonParams.MDNSPorts, "mdns-ports", "", "5353", "The list of UDP ports to listen on for mDNS poisoning (opt-in)")

	// Advertised (spoofed) addresses. When unset, the address of the interface
	// the query arrived on is used; if none can be determined, nothing is
	// answered (the query is still observed and logged).
	rootCmd.Flags().StringVarP(&poisonParams.SpoofIPv4, "poison-spoof-ip", "", "", "The IPv4 address to answer poisoned queries with (default: the arrival interface's address)")
	rootCmd.Flags().StringVarP(&poisonParams.SpoofIPv6, "poison-spoof-ip6", "", "", "The IPv6 address to answer poisoned queries with (default: the arrival interface's address)")
	rootCmd.Flags().StringVarP(&poisonParams.AnswerName, "poison-answer-name", "", "", "Optional LLMNR answer-record name, overriding the queried name")
	rootCmd.Flags().IntVarP(&poisonParams.TTL, "poison-ttl", "", -1, "Override the answer TTL (seconds) for all poisoners; -1 keeps per-protocol defaults")

	// Scoping policy. These exist so an operator can keep answers inside an
	// authorized engagement scope; --poison-analyze observes and logs without
	// answering anything.
	rootCmd.Flags().StringVarP(&poisonParams.RespondTo, "poison-respond-to", "", "", "Only answer queries from these source addresses (comma list of IP, CIDR, or range)")
	rootCmd.Flags().StringVarP(&poisonParams.DontRespondTo, "poison-dont-respond-to", "", "", "Never answer queries from these source addresses (comma list of IP, CIDR, or range)")
	rootCmd.Flags().StringVarP(&poisonParams.RespondToName, "poison-respond-to-name", "", "", "Only answer queries for these names (comma list, case-insensitive)")
	rootCmd.Flags().StringVarP(&poisonParams.DontRespondToName, "poison-dont-respond-to-name", "", "ISATAP", "Never answer queries for these names (comma list, case-insensitive)")
	rootCmd.Flags().StringVarP(&poisonParams.DontRespondToTLD, "poison-dont-respond-to-tld", "", "_dosvc", "Never answer queries whose name ends with these suffixes (comma list)")
	rootCmd.Flags().BoolVarP(&poisonParams.Analyze, "poison-analyze", "", false, "Analyze mode: observe and log poisoner queries but answer nothing")
}

// poisonPolicy builds the shared scope policy from the poisoner flags.
func poisonPolicy() *flamingo.ScopePolicy {
	policy, err := flamingo.NewScopePolicy(
		poisonParams.RespondTo,
		poisonParams.DontRespondTo,
		poisonParams.RespondToName,
		poisonParams.DontRespondToName,
		poisonParams.DontRespondToTLD,
		poisonParams.Analyze,
	)
	if err != nil {
		log.Fatalf("invalid poisoner scope policy: %s", err)
	}
	return policy
}

func setupLLMNR(rw *flamingo.RecordWriter) {
	policy := poisonPolicy()
	startListeners("llmnr", poisonParams.LLMNRPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfLLMNR()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.Policy = policy
		conf.SpoofIPv4 = poisonParams.SpoofIPv4
		conf.SpoofIPv6 = poisonParams.SpoofIPv6
		conf.AnswerName = poisonParams.AnswerName
		if poisonParams.TTL >= 0 {
			conf.TTL = uint32(poisonParams.TTL)
		}
		return conf.Shutdown, flamingo.SpawnLLMNR(conf)
	})
}

func setupNBTNS(rw *flamingo.RecordWriter) {
	policy := poisonPolicy()
	startListeners("nbtns", poisonParams.NBTNSPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfNBTNS()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.Policy = policy
		conf.SpoofIPv4 = poisonParams.SpoofIPv4
		if poisonParams.TTL >= 0 {
			conf.TTL = uint32(poisonParams.TTL)
		}
		return conf.Shutdown, flamingo.SpawnNBTNS(conf)
	})
}

func setupMDNS(rw *flamingo.RecordWriter) {
	policy := poisonPolicy()
	startListeners("mdns", poisonParams.MDNSPorts, func(port uint16) (func(), error) {
		conf := flamingo.NewConfMDNS()
		conf.BindPort = port
		conf.RecordWriter = rw
		conf.Policy = policy
		conf.SpoofIPv4 = poisonParams.SpoofIPv4
		conf.SpoofIPv6 = poisonParams.SpoofIPv6
		if poisonParams.TTL >= 0 {
			conf.TTL = uint32(poisonParams.TTL)
		}
		return conf.Shutdown, flamingo.SpawnMDNS(conf)
	})
}
