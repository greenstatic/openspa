package cmd

import (
	"fmt"
	"os"

	"github.com/greenstatic/openspa/internal"
	"github.com/spf13/cobra"
)

var IPCmd = &cobra.Command{
	Use:    "ip",
	Short:  "Returns the client's public IPv4 and IPv6 address",
	Run:    ipCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

func IPCmdSetup(c *cobra.Command) {
	c.Flags().StringP("ipv4-server", "4", internal.IPv4ServerDefault,
		"The server to use to resolve client's public IPv4 address (needs to be a URL)")

	c.Flags().StringP("ipv6-server", "6", internal.IPv6ServerDefault,
		"The server to use to resolve client's public IPv6 address (needs to be a URL)")
}

func ipCmdRunFn(cmd *cobra.Command, args []string) {
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

	internal.GetIP(v4, v6)
}
