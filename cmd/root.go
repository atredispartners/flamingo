package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ToolName = "flamingo"
var Version = "0.0.1"
var BuildDate = "2020-01-10"

type flamingoParameters struct {
	Verbose    bool
	SNMPPorts  string
	SSHPorts   string
	SSHHostKey string
	Protocols  string
}

var params = &flamingoParameters{}

var rootCmd = &cobra.Command{
	Use:   ToolName,
	Short: fmt.Sprintf("%s captures inbound credentials", ToolName),
	Long:  fmt.Sprintf(`flamingo v%s [%s]`, Version, BuildDate),
	Args:  cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		startCapture(cmd, args)
	},
}

// Execute is the main entry point for this tool
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// General options
	rootCmd.PersistentFlags().BoolVarP(&params.Verbose, "verbose", "v", false, "Display verbose output")
	rootCmd.Flags().StringVarP(&params.Protocols, "protocols", "", "ssh,snmp", "Specify a comma-separated list of protocols")

	// SNMP parameters
	rootCmd.Flags().StringVarP(&params.SNMPPorts, "snmp-ports", "", "161", "The list of UDP ports to listen on for SNMP")

	// SSH parameters
	rootCmd.Flags().StringVarP(&params.SSHPorts, "ssh-ports", "", "22", "The list of TCP ports to listen on for SSH")
	rootCmd.Flags().StringVarP(&params.SSHHostKey, "ssh-host-key", "", "", "An optional path to a SSH host key on disk")
}
