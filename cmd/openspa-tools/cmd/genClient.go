package cmd

import (
	"github.com/greenstatic/openspalib/cryptography"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/greenstatic/openspa/internal/genOspa"
	"os"
	"path/filepath"
)

var ouputDir string

var genClientCmd = &cobra.Command{
	Use:   "gen-client [server public key]",
	Short: "Generates OpenSPA client configuration file (OSPA file)",
	Long: `This command will generate an OpenSPA OSPA client configuration file
which the client can use to connect to the OpenSPA server.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		serverPubKeyPath := args[0]

		// Get the servers public key
		serverPubKeyContent, err := genOspa.FileContents(serverPubKeyPath)
		if err != nil {
			os.Exit(badInputParameters)
			return
		}

		serverPubKey, err := cryptography.DecodeX509PublicKeyRSA(serverPubKeyContent)
		if err != nil {
			log.Error("Failed to parse server x509 RSA public key")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		log.WithField("path", serverPubKeyPath).Info("Using server public key")

		// Check that the output path exists

		outputDirFull := genOspa.BuildAbsPath(ouputDir)

		if !pathExists(outputDirFull) {
			log.WithField("path", outputDirFull).Error("Output dir does not exist")
			os.Exit(badInputParameters)
			return
		}

		// Go through the walkthrough to get all the OSPA field values
		fieldVals, err := genOspa.AskClientOSPAFileParameters(serverPubKey)
		if err != nil {
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// Create the byte contents of the OSPA file
		ospaFileContents, err := fieldVals.Generate()
		if err != nil {
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// Create the base directory in output-dir
		outputPath := filepath.Join(outputDirFull, fieldVals.ClientDeviceID)
		err = os.Mkdir(outputPath, os.ModePerm)
		if err != nil {
			log.WithField("path", outputPath).
				Error("Failed to create client's configuration directory inside the output directory")
			os.Exit(unexpectedError)
			return
		}

		// Write the OSPA file
		ospaFPath := filepath.Join(outputPath, "client.ospa")
		ospaF, err := os.Create(ospaFPath)
		defer ospaF.Close()
		if err != nil {
			log.WithField("path", ospaFPath).Error("Failed to create OSPA file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		_, err = ospaF.Write(ospaFileContents)
		if err != nil {
			log.WithField("path", ospaFPath).Error("Failed to write to OSPA file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// Write the client's public key
		clientPubPath := filepath.Join(outputPath, fieldVals.ClientDeviceID+".pub")
		clientPubF, err := os.Create(clientPubPath)
		defer clientPubF.Close()
		if err != nil {
			log.WithField("path", clientPubPath).Error("Failed to create client's public key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		clientPubByte, err := genOspa.EncodeRSAPublicKey(fieldVals.PublicKey)
		if err != nil {
			os.Exit(unexpectedError)
			return
		}

		_, err = clientPubF.Write(clientPubByte)
		if err != nil {
			log.WithField("path", clientPubPath).Error("Failed to write client's public key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		log.WithFields(log.Fields{
			"clientOSPAFilePath": ospaFPath,
			"clientPublicKey":    clientPubPath,
		}).
			Info("Successfully create the clients configuration files")

	},
}

func init() {
	genClientCmd.Flags().StringVarP(&ouputDir, "output-dir", "o", "./",
		"Path of the output directory where we will write the OSPA file and the client's public key")
	rootCmd.AddCommand(genClientCmd)
}
