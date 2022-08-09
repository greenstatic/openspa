package cmd

import (
	"fmt"
	"os"

	"github.com/greenstatic/openspa/internal/client"
	"github.com/spf13/cobra"
)

var ipCmd = &cobra.Command{
	Use:   "ip",
	Short: "Returns the client's public IPv4 and IPv6 address",

	Run: func(cmd *cobra.Command, args []string) {
		v4, err := cmd.Flags().GetString("ipv4-server")
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ipv4-server, err: %s\n", err)
			os.Exit(1)
		}
		v6, err := cmd.Flags().GetString("ipv6-server")
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ipv6-server, err: %s\n", err)
			os.Exit(1)
		}

		client.GetIP(v4, v6)
	},
	PreRun: preRunLogSetupFun,
}

func ipCmdInit() {
	ipCmd.Flags().StringP("ipv4-server", "4", client.IPv4ServerDefault,
		"The server to use to resolve client's public IPv4 address (needs to be a URL)")

	ipCmd.Flags().StringP("ipv6-server", "6", client.IPv6ServerDefault,
		"The server to use to resolve client's public IPv6 address (needs to be a URL)")
}
