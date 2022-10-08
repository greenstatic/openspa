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
	Use:   "openspa-client",
	Short: "Send OpenSPA request packets to get access to hidden services",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PreRun: cmd.PreRunLogSetupFn,
}

func rootCmdSetup(c *cobra.Command) {
	cmd.RootCmdSetupFlags(c)

	c.AddCommand(cmd.IPCmd)
	cmd.IPCmdSetup(cmd.IPCmd)

	c.AddCommand(cmd.ReqCmd)
	cmd.ReqCmdSetup(cmd.ReqCmd)

	c.AddCommand(cmd.VersionCmdGet(false))
}
