package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "openspa-client",
	Short: "Send OpenSPA request packets to get access to hidden services",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func Execute() {
	setupCommands()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupCommands() {
	rootCmd.AddCommand(ipCmd)
	ipCmdInit()

	rootCmd.AddCommand(versionCmd)

}
