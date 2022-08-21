package main

import (
	"fmt"
	"os"

	"github.com/greenstatic/openspa/internal/cmd"
	"github.com/spf13/cobra"
)

func main() {
	rootCmdSetup(cmd.ServerCmd)
	if err := cmd.ServerCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func rootCmdSetup(c *cobra.Command) {
	cmd.RootCmdSetupFlags(c)
	cmd.ServerCmdSetup(c)

	c.AddCommand(cmd.VersionCmd)
}
