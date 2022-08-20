package cmd

import (
	"github.com/spf13/cobra"
)

var ServerCmd = &cobra.Command{
	Use:    "server <config.yaml>",
	Short:  "Start OpenSPA server",
	Run:    serverCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

func ServerCmdSetup(c *cobra.Command) {

}

func serverCmdRunFn(cmd *cobra.Command, args []string) {

}
