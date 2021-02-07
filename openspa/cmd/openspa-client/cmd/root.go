package cmd

import (
	"bytes"
	"fmt"
	"github.com/greenstatic/openspa/internal/client"
	"github.com/greenstatic/openspalib"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var (
	Verbose      bool
	VerboseSplit bool
	ver          bool
)

var rootCmd = &cobra.Command{
	Use:   "openspa-client",
	Short: "OpenSPA client to send OpenSPA request packets",
	Long: `OpenSPA client allows to send OpenSPA request packets to remotely 
open firewall ports on the desired OpenSPA server.`,
	Run: func(cmd *cobra.Command, args []string) {
		if ver {
			fmt.Printf("OpenSPA client version: %s\n", client.Version)
			fmt.Printf("OpenSPA protocol version: %d\n", openspalib.Version)
			return
		}
		cmd.Help()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&VerboseSplit, "verbose-split", false,
		"split output to stdout (until but not including error level) and stderr (error level)")
	rootCmd.Flags().BoolVar(&ver, "version", false, "Version of the client and supported features")

	log.SetOutput(os.Stdout)
	cobra.OnInitialize(verboseSplit)
	cobra.OnInitialize(verboseLog)
}

// Used to route error level logs to stderr and the rest to stdout.
// Credits: https://github.com/sirupsen/logrus/issues/403#issuecomment-346437512
// This disables the feature of color output in case it's ran from a TTY.
type OutputSplitter struct{}

func (splitter *OutputSplitter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("level=error")) {
		return os.Stderr.Write(p)
	}
	return os.Stdout.Write(p)
}

// Enables verbose split - until error level to stdout, while error goes to stderr.
// This is to be used on cobra.OnInitialize() to enable globally for all commands
// if the verbose-split flag is present.
func verboseSplit() {
	if VerboseSplit {
		log.SetOutput(&OutputSplitter{})
	}
}

// Enables verbose logging (debug level logs). This is to be used on cobra.OnInitialize()
// to enable globally for all commands if the verbose flag is present.
func verboseLog() {
	if Verbose {
		log.SetLevel(log.DebugLevel)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(unexpectedError)
	}
}
