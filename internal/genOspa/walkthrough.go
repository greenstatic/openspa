package genOspa

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"github.com/greenstatic/openspa/internal/ospa"
	"github.com/greenstatic/openspalib/cryptography"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type OSPAFileParameters struct {
	ConfigName      string
	ClientDeviceID  string
	ServerIP        net.IP
	ServerPort      uint16
	EchoIPServer    string
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	ServerPublicKey *rsa.PublicKey
}

const defaultConfigName = "SPA server"

func AskClientOSPAFileParameters(serverPublicKey *rsa.PublicKey) (OSPAFileParameters, error) {

	if serverPublicKey == nil {
		log.Error("Missing server public key")
		return OSPAFileParameters{}, errors.New("missing server public key")
	}

	ospaParams := OSPAFileParameters{}
	ospaParams.ServerPublicKey = serverPublicKey

	fmt.Println("If you press enter we will select the default value.")

	// Ask config name
	configName, err := askUser(
		"Config name (default: \"SPA server\"): ",
		"^[\\w #-]*[\n\r]*$",
		defaultConfigName,
		true,
		true,
	)
	if err != nil {
		log.Error("Provided an invalid config name, allowed characters: a-zA-Z0-9_ #-")
		return OSPAFileParameters{}, errors.New("bad config name input")
	}

	log.WithField("configName", configName).Info("Set config name")
	ospaParams.ConfigName = configName

	// Ask client device ID or generate a new one
	clientDeviceId, err := askUser(
		"Client Device ID (UUIDv4 with dashes and lower case) (default: generate a random UUIDv4): ",
		"[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}",
		"",
		true,
		false,
	)

	if clientDeviceId == "" {
		log.Debug("Generating random client device UUID...")
		clientDeviceId = uuid.Must(uuid.NewV4(),err).String()
		log.WithField("clientDeviceId", clientDeviceId).Info("Generated random client device UUID")
	}

	ospaParams.ClientDeviceID = clientDeviceId

	// Ask server IP (optional)
	serverIp, err := askUser(
		"Server IP (optional) (default: \"\"): ",
		"",
		"",
		true,
		false,
	)

	if net.ParseIP(serverIp) == nil {
		log.Info("Not using server IP field")
		ospaParams.ServerIP = nil
	} else {
		log.WithField("serverIp", serverIp).Info("Set server IP")
		ospaParams.ServerIP = net.ParseIP(serverIp)
	}

	// Ask server port (optional)
	defualtServerPortStr := strconv.Itoa(int(ospa.DefaultServerPort))
	serverPort, err := askUser(
		fmt.Sprintf("Server port (default: %s): ", defualtServerPortStr),
		getUin16WithoutZeroRegexString(),
		defualtServerPortStr,
		true,
		true,
	)
	if err != nil {
		log.Error("Provided an invalid port")
		return OSPAFileParameters{}, errors.New("bad port input")
	}

	serverPortInt, _ := strconv.Atoi(serverPort)
	log.WithField("port", serverPortInt).Info("Set port")
	ospaParams.ServerPort = uint16(serverPortInt)

	// Ask Echo-IP server (optional)
	echoIp, err := askUser(
		fmt.Sprintf("Echo-IP server (default: %s): ", ipresolver.DefaultEchoIpV4Server),
		"^(http|https):\\/\\/[\\w-.]+$",
		ipresolver.DefaultEchoIpV4Server,
		true,
		true,
	)
	if err != nil {
		log.Error("Provided an invalid Echo-IP server")
		return OSPAFileParameters{}, errors.New("bad echo-ip server")
	}
	log.WithField("echoIpServer", echoIp).Info("Set Echo-IP server")
	ospaParams.EchoIPServer = echoIp

	// Ask private and public key path or generate a new key-pair
	var privKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey

	for {
		// Private key path
		privKeyPath, _ := askUser(
			"Client private key path: (default: generate a new private/public keypair): ",
			"",
			"",
			true,
			false,
		)

		// Generate new private/public key-pair if private-key is empty
		if privKeyPath == "" {
			break
		}

		// Check if valid private key file
		privKeyContent, err := FileContents(privKeyPath)
		if err != nil {
			continue
		}

		privKey, err = cryptography.DecodeX509PrivateKeyRSA(privKeyContent)
		if err != nil {
			log.Error("Failed to parse x509 RSA private key")
			log.Error(err)
			privKey = nil
			continue
		}

		// Public key path

		pubKeyPath, _ := askUser(
			"Client public key path: (default: generate a new private/public keypair): ",
			"",
			"",
			true,
			false,
		)

		// Generate new private/public key-pair if public-key is empty
		if pubKeyPath == "" {
			break
		}

		// Check if valid public key file
		pubKeyContent, err := FileContents(pubKeyPath)
		if err != nil {
			continue
		}

		pubKey, err = cryptography.DecodeX509PublicKeyRSA(pubKeyContent)
		if err != nil {
			log.Error("Failed to parse x509 RSA public key")
			log.Error(err)
			pubKey = nil
			continue
		}

		log.WithFields(log.Fields{
			"privateKeyPath": privKeyPath,
			"publicKeyPath":  pubKeyPath,
		}).
			Info("Successfully loaded private/public key-pair from provided files")

		break // successfully got private/public key-pair from the provided files
	}

	// Generate new key-pair if private/public key-pair is empty
	if privKey == nil || pubKey == nil {
		privKey, pubKey, err = GeneratePrivatePublicKeyPair()
		if err != nil {
			return OSPAFileParameters{}, err
		}
	}

	ospaParams.PrivateKey = privKey
	ospaParams.PublicKey = pubKey

	return ospaParams, nil
}

// Returns the regex string to verify if a string is a valid non-zero uint16 digit (to verify if a port string is valid)
func getUin16WithoutZeroRegexString() string {
	return "^([1-9][0-9]{0,3}|[1-5][0-9]{0,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
}

// Asks the user for the requested input. We check the requested input against the regex.
// If the users input is an empty string, we will set the default value if the useDefaultValue
// bool is set to true, otherwise we will ask the user again (if the continuousRequest bool is
// set to true). If regex string is empty then we will skip the regex check and return the value
// immediately.
func askUser(instructions, regex, defaultValue string, useDefaultValue, continuousRequest bool) (input string, err error) {

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(instructions)
		input, _ = reader.ReadString('\n')
		input = trimControlCharacters(input)

		if useDefaultValue && input == "" {
			return defaultValue, nil
		}

		if regex == "" {
			// Bypass regex check
			return
		}

		// Verify input
		if match, _ := regexp.MatchString(regex, input); !match {
			if continuousRequest {
				continue
			}
			return "", errors.New("bad input")
		}

		return input, nil
	}

}

// Accepts a relative path (using the executable as the working directory) or an absolute path of
// a file and opens it while returning the contents.
func FileContents(path string) ([]byte, error) {

	// Build the absolute path of the file
	fullPath := BuildAbsPath(path)

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.WithField("absolutePath", fullPath).Error("Provided file does not exist")
		return nil, errors.New("file does not exist")
	}

	b, err := ioutil.ReadFile(fullPath)
	if err != nil {
		log.WithField("absolutePath", fullPath).Error("Failed to open file")
		return nil, errors.New("cannot open file")
	}

	return b, nil
}

// Returns an absolute path from the provided path using the executable as the working directory if the
// provided path is relative. Otherwise it simply returns the provided path since it's absolute. If
// we fail to get the path of the executable we panic.
func BuildAbsPath(path string) string {
	if !filepath.IsAbs(path) {
		execPath, err := os.Executable()
		if err != nil {
			log.Error("Failed to find absolute path of the executable, try using ab absolute path instead of a relative one")
			panic(err)
		}

		return filepath.Join(filepath.Dir(execPath), path)
	}
	return path
}

// Generates a RSA private/public key-pair.
func GeneratePrivatePublicKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {

	const size = 2048

	privKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		log.Error("Failed to generate private key")
		log.Error(err)
		return nil, nil, err
	}
	pubKey := &privKey.PublicKey

	return privKey, pubKey, nil

}

// Returns the string without the suffix of \r or \n
func trimControlCharacters(s string) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	s = strings.TrimSuffix(s, "\n")
	return s
}
