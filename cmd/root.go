package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// ToolName controls what this program thinks it is
var ToolName = "flamingo"

// Version is set by goreleaser
var Version = "0.0.0"

type flamingoParameters struct {
	Quiet              bool
	Verbose            bool
	DontIgnoreFailures bool
	FTPPorts           string
	DNSPorts           string
	DNSResolveToIP     string
	SNMPPorts          string
	SSHPorts           string
	SSHHostKey         string
	LDAPPorts          string
	LDAPSPorts         string
	HTTPPorts          string
	HTTPSPorts         string
	HTTPBasicRealm     string
	HTTPAuthMode       string
	TLSCertFile        string
	TLSCertData        string
	TLSKeyFile         string
	TLSKeyData         string
	TLSName            string
	TLSOrgName         string
	Protocols          string
}

var params = &flamingoParameters{}

var rootCmd = &cobra.Command{
	Use:   ToolName,
	Short: fmt.Sprintf("%s captures inbound credentials", ToolName),
	Long:  fmt.Sprintf(`flamingo v%s`, Version),
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
	rootCmd.PersistentFlags().BoolVarP(&params.Quiet, "quiet", "q", false, "Hide startup banners and other extraneous output")
	rootCmd.PersistentFlags().BoolVarP(&params.DontIgnoreFailures, "dont-ignore", "", false, "Treat individual listener failures as fatal")

	rootCmd.Flags().StringVarP(&params.Protocols, "protocols", "", "ssh,snmp,ldap,http,dns,ftp", "Specify a comma-separated list of protocols")

	// SNMP parameters
	rootCmd.Flags().StringVarP(&params.SNMPPorts, "snmp-ports", "", "161", "The list of UDP ports to listen on for SNMP")

	// SSH parameters
	rootCmd.Flags().StringVarP(&params.SSHPorts, "ssh-ports", "", "22", "The list of TCP ports to listen on for SSH")
	rootCmd.Flags().StringVarP(&params.SSHHostKey, "ssh-host-key", "", "", "An optional path to a SSH host key on disk")

	// LDAP(S) parameters
	rootCmd.Flags().StringVarP(&params.LDAPPorts, "ldap-ports", "", "389", "The list of TCP ports to listen on for LDAP")
	rootCmd.Flags().StringVarP(&params.LDAPSPorts, "ldaps-ports", "", "636", "The list of TCP ports to listen on for LDAPS")

	// DNS parameters
	rootCmd.Flags().StringVarP(&params.DNSPorts, "dns-ports", "", "53,5353", "The list of UDP ports to listen on for DNS")
	rootCmd.Flags().StringVarP(&params.DNSResolveToIP, "dns-resolve-to", "", "", "The IP address used to respond to DNS Type A question. If empty, no response will be sent")

	// FTP parameters
	rootCmd.Flags().StringVarP(&params.FTPPorts, "ftp-ports", "", "21", "The list of TCP ports to listen on for FTP")

	// HTTP(S) parameters
	rootCmd.Flags().StringVarP(&params.HTTPPorts, "http-ports", "", "80", "The list of TCP ports to listen on for HTTP")
	rootCmd.Flags().StringVarP(&params.HTTPSPorts, "https-ports", "", "443", "The list of TCP ports to listen on for HTTPS")
	rootCmd.Flags().StringVarP(&params.HTTPBasicRealm, "http-realm", "", "Administration", "The HTTP basic authentication realm to present")
	rootCmd.Flags().StringVarP(&params.HTTPAuthMode, "http-auth-mode", "", "ntlm", "The authentication mode for the HTTP listeners (ntlm or basic)")

	rootCmd.Flags().StringVarP(&params.TLSCertFile, "tls-cert", "", "", "An optional x509 certificate for TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSKeyFile, "tls-key", "", "", "An optional x509 key for TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSName, "tls-name", "", "localhost", "A server name to use with TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSOrgName, "tls-org", "", "Flamingo Feed, Inc.", "An organization to use for self-signed certificates")
}
