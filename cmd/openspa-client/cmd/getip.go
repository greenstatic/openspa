package cmd

import (
	"github.com/greenstatic/openspa/internal/cmdimpl"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"github.com/spf13/cobra"
	"os"
)

var (
	echoIPv4Server string
	echoIPv6Server string
)

var getIPCmd = &cobra.Command{
	Use:   "get-ip",
	Short: "Returns the client's outbound, public IP's and if they are behind NAT",
	Long: `Returns the client's (often private) outbound IP that it uses for default routes and 
the client's public IP by sending a request to an external service. As well as resolves if the 
client is behind a nat`,

	Run: func(cmd *cobra.Command, args []string) {

		if err := cmdimpl.GetIP(echoIPv4Server, echoIPv6Server); err != nil {
			os.Exit(unexpectedError)
			return
		}

	},
}

func init() {
	getIPCmd.Flags().StringVarP(&echoIPv4Server, "echo-ipv4-server", "",
		ipresolver.DefaultEchoIpV4Server,
		"The IPv4 Echo-IP server to use for public IPv4 resolution (needs to be a URL)")

	getIPCmd.Flags().StringVarP(&echoIPv6Server, "echo-ipv6-server", "",
		ipresolver.DefaultEchoIpV6Server,
		"The IPv6 Echo-IP server to use for public IPv4 resolution (needs to be a URL)")

	rootCmd.AddCommand(getIPCmd)
}
