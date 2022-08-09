package cmd

import (
	"fmt"

	"github.com/greenstatic/openspa/internal/client"
	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Return's the client version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("OpenSPA Client version: %s\n", client.Version())
		fmt.Printf("OpenSPA Protocol version: %s\n", lib.Version())
	},
	PreRun: preRunLogSetupFun,
}
