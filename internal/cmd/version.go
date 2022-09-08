package cmd

import (
	"fmt"

	"github.com/greenstatic/openspa/internal"
	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/spf13/cobra"
)

var VersionCmd = &cobra.Command{
	Use: "version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("THIS IS PROTOTYPE SOFTWARE")
		fmt.Printf("OpenSPA version: %s\n", internal.Version())
		fmt.Printf("OpenSPA Protocol version: %s\n", lib.Version())
	},
	PreRun: PreRunLogSetupFn,
}