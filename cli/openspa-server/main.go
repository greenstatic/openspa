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
	Use:   "openspa-server",
	Short: "OpenSPA server authorize user's IP to access hidden services using a single packet",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PreRun: cmd.PreRunLogSetupFn,
}

func rootCmdSetup(c *cobra.Command) {
	cmd.RootCmdSetupFlags(c)

	rootCmd.AddCommand(cmd.VersionCmd)
}
