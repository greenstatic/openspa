package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/greenstatic/openspa/internal/genOspa"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

var (
	privKeyPath string
	pubKeyPath  string
)

var genServerKeyCmd = &cobra.Command{
	Use:   "gen-server-key",
	Short: "Generates OpenSPA server key",
	Long:  `This command will generate an RSA key-pair for the OpenSPA server.`,
	Run: func(cmd *cobra.Command, args []string) {

		// Check if the provided base paths exist for the private/public keys
		privKeyBasePath := filepath.Dir(genOspa.BuildAbsPath(privKeyPath))
		if !pathExists(privKeyBasePath) {
			log.WithField("path", privKeyBasePath).Error("Base path for the private key does not exist")
			os.Exit(badInputParameters)
			return
		}
		pubKeyBasePath := filepath.Dir(genOspa.BuildAbsPath(pubKeyPath))
		if !pathExists(pubKeyBasePath) {
			log.WithField("path", pubKeyBasePath).Error("Base path for the public key does not exist")
			os.Exit(badInputParameters)
			return
		}

		// Generate the key-pair
		privKey, pubKey, err := genOspa.GeneratePrivatePublicKeyPair()
		if err != nil {
			os.Exit(unexpectedError)
			return
		}

		// Write the private key file
		kF, err := os.Create(privKeyPath)
		defer kF.Close()
		if err != nil {
			log.WithField("path", privKeyPath).Error("Failed to create private key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// convert private key from DER to PEM
		privKeyPEM := pem.Block{
			"RSA PRIVATE KEY",
			nil,
			x509.MarshalPKCS1PrivateKey(privKey),
		}

		if err = pem.Encode(kF, &privKeyPEM); err != nil {
			log.WithField("path", privKeyPath).Error("Failed to write to the private key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// Write the public key file
		pF, err := os.Create(pubKeyPath)
		defer pF.Close()
		if err != nil {
			log.WithField("path", pubKeyPath).Error("Failed to create public key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			log.Error("Failed to extract public key to DER format")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		// convert public key from DER to PEM
		pubKeyPEM := pem.Block{
			"PUBLIC KEY",
			nil,
			pubKeyBytes,
		}

		if err = pem.Encode(pF, &pubKeyPEM); err != nil {
			log.WithField("path", privKeyPath).Error("Failed to write to the public key file")
			log.Error(err)
			os.Exit(unexpectedError)
			return
		}

		log.WithFields(log.Fields{
			"privateKeyPath": privKeyPath,
			"publicKeyPath":  pubKeyPath,
		}).Info("Successfully created server key-pair")

	},
}

// Returns a boolean if the path exists or not.
func pathExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

func init() {
	genServerKeyCmd.Flags().StringVarP(&privKeyPath, "key-file", "k", "./server.key",
		"Path of the generated private key file")

	genServerKeyCmd.Flags().StringVarP(&pubKeyPath, "pub-file", "p", "./server.pub",
		"Path of the generated public key file")

	rootCmd.AddCommand(genServerKeyCmd)
}
