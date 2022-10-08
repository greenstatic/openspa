package cmd

import (
	"fmt"

	"github.com/greenstatic/openspa/internal"
	"github.com/greenstatic/openspa/internal/xdp"
	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/spf13/cobra"
)

func VersionCmdGet(withADKXDPLine bool) *cobra.Command {
	return &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("THIS IS PROTOTYPE SOFTWARE")
			fmt.Printf("OpenSPA version: %s\n", internal.Version())
			fmt.Printf("OpenSPA Protocol version: %s\n", lib.Version())

			if withADKXDPLine {
				fmt.Printf("adk XDP support: %t\n", xdp.IsSupported())
			}
		},
		PreRun: PreRunLogSetupFn,
	}
}
