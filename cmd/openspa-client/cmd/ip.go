package cmd

import (
	"github.com/greenstatic/openspa/internal/client"
	"github.com/spf13/cobra"
)

var (
	ipv4Server string
	ipv6Server string
)

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Returns the client's public IPv4 and IPv6 address",

	Run: func(cmd *cobra.Command, args []string) {
		client.GetIP(ipv4Server, ipv6Server)
	},
}

func ipCmdInit() {
	ipCmd.Flags().StringVarP(&ipv4Server, "ipv4-server", "4",
		client.IPv4ServerDefault,
		"The server to use to resolve client's public IPv4 address (needs to be a URL)")

	ipCmd.Flags().StringVarP(&ipv6Server, "ipv6-server", "6",
		client.IPv6ServerDefault,
		"The server to use to resolve client's public IPv6 address (needs to be a URL)")
}
