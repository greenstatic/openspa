package main

import (
	"fmt"
	"os"

	"github.com/greenstatic/openspa/internal/cmd"
	"github.com/spf13/cobra"
)

func main() {
	rootCmdSetup(rootCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use: "openspa",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PreRun: cmd.PreRunLogSetupFn,
}

func rootCmdSetup(c *cobra.Command) {
	cmd.RootCmdSetupFlags(c)

	c.AddCommand(clientCmd)
	clientCmdSetup(clientCmd)

	c.AddCommand(cmd.ServerCmd)
	cmd.ServerCmdSetup(cmd.ServerCmd)

	c.AddCommand(cmd.ADKCmd)
	cmd.ADKCmdSetup(cmd.ADKCmd)

	c.AddCommand(cmd.VersionCmd)
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Send OpenSPA request packets to get access to hidden services",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PreRun: func(c *cobra.Command, args []string) {
		cmd.PreRunLogSetupFn(c, args)
	},
}

func clientCmdSetup(c *cobra.Command) {
	c.AddCommand(cmd.ReqCmd)
	cmd.ReqCmdSetup(cmd.ReqCmd)

	c.AddCommand(cmd.IPCmd)
	cmd.IPCmdSetup(cmd.IPCmd)
}
