package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "openspa-client",
	Short: "Send OpenSPA request packets to get access to hidden services",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
	PreRun: preRunLogSetupFun,
}

func Execute() {
	setupCommands()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupCommands() {
	rootCmdInit()

	rootCmd.AddCommand(ipCmd)
	ipCmdInit()

	rootCmd.AddCommand(reqCmd)
	reqCmdInit()

	rootCmd.AddCommand(versionCmd)
}

func rootCmdInit() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose logging (debug level and higher)")
}

func preRunLogSetupFun(cmd *cobra.Command, args []string) {
	verbose, _ := cmd.Flags().GetBool("verbose")
	logSetup(verbose)
}

func logSetup(verbose bool) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Level(zerolog.InfoLevel)
	if verbose {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}
}
