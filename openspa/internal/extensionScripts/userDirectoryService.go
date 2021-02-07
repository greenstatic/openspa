package extensionScripts

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"github.com/greenstatic/openspalib/cryptography"
	log "github.com/sirupsen/logrus"
	"os/exec"
)

type userDirectoryService struct {
	rootDir string
	cmd     string
}

// Launches the UserDirectoryService script with the subcommand "GET_USER_PUBLIC_KEY"
// which should return the requested user's public key. In case the user does not
// have a public key a nill value should be provided without an error. If something
// goes wrong then return an error.
// TODO - follow the above rules (if pub key does not exist currently it will trigger an error)
func (uds *userDirectoryService) UserPublicKey(clientDeviceID string) (*rsa.PublicKey, error) {
	const argumentCommand = "GET_USER_PUBLIC_KEY"

	if uds.cmd == "" {
		log.Error("UserDirectoryService struct does not contain a command string to execute")
		return nil, errors.New("no cmd")
	}

	cmd := exec.Command(uds.cmd, argumentCommand, clientDeviceID)
	cmd.Dir = uds.rootDir

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Warning since it's not necessary that the user actually has their public key
		// within the user directory service - therefore is unauthorized
		log.WithField("clientDeviceId", clientDeviceID).
			Warning("UserDirectoryService script GET_USER_PUBLIC_KEY command responded with a failure")
		log.Warning(err)
		return nil, err
	}

	// Try to parse the returned public key
	pubKey, err := cryptography.DecodeX509PublicKeyRSA(stdout.Bytes())
	if err != nil {
		log.WithField("clientDeviceId", clientDeviceID).
			Error("Failed to decode received public key from UserDirectoryService script")
		log.Error(err)
		log.Error(stdout.String())
		log.Error(stderr.String())
		return nil, err
	}

	log.WithField("clientDeviceId", clientDeviceID).Debug("Found user's public key")

	return pubKey, nil
}
