package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func RootCmdSetupFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose logging (debug level and higher)")
}

func PreRunLogSetupFn(cmd *cobra.Command, args []string) {
	verbose, _ := cmd.Flags().GetBool("verbose")
	LogSetup(verbose)
}

func LogSetup(verbose bool) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if verbose {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}
}
