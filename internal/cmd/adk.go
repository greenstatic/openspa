package cmd

import (
	"fmt"
	"os"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/spf13/cobra"
)

var ADKCmd = &cobra.Command{
	Use:    "adk",
	Short:  "Anti DoS Knocking utilities",
	Run:    adkCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

var ADKSecretCmd = &cobra.Command{
	Use:    "secret",
	Short:  "Generate ADK (encoded) secret",
	Run:    adkSecretCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

var ADKProofCmd = &cobra.Command{
	Use:    "proof [ADK secret]",
	Short:  "Generate ADK proof",
	Run:    adkProofCmdRunFn,
	PreRun: PreRunLogSetupFn,
	Args:   cobra.ExactArgs(1),
}

func ADKCmdSetup(c *cobra.Command) {
	c.AddCommand(ADKSecretCmd)
	c.AddCommand(ADKProofCmd)
}

func adkCmdRunFn(cmd *cobra.Command, args []string) {
	_ = cmd.Help()
}

func adkSecretCmdRunFn(cmd *cobra.Command, args []string) {
	secret, err := openspalib.ADKGenerateSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate ADK secret, err: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Secret: %s\n", secret)
}

func adkProofCmdRunFn(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "invalid number of arguments\n")
		os.Exit(1)
	}

	secret := args[0]

	proof, err := openspalib.ADKGenerateProof(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate ADK proof, err: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "Proof: %d\n", proof)
}
