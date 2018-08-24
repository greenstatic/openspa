package ospa

import (
	"errors"
	"github.com/greenstatic/openspa/internal/client"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net"
	"regexp"
	"strconv"
)

const DefaultServerPort uint16 = 22211

type OSPA struct {
	Version            string `yaml:"version"`
	Name               string `yaml:"name"`
	ClientDeviceID     string `yaml:"clientDeviceId"`
	ServerIP           net.IP `yaml:"serverIp"`
	ServerPort         uint16 `yaml:"serverPort"`
	EchoIpServer       string `yaml:"echoIpServer"`
	PrivateKeyStr      string `yaml:"privateKey"`
	PublicKeyStr       string `yaml:"publicKey"`
	ServerPublicKeyStr string `yaml:"serverPublicKey"`
}

// Returns boolean if the OSPA struct is not empty.
func (o *OSPA) Exists() bool {
	// Since an empty string is not an allowed version,
	// simply check if it is not equal to an empty string
	// to determine if struct has been initialized

	return o.Version != ""
}

// Parses the contents of an OSPA file and if successful return an OSPA struct.
func Parse(data []byte) (OSPA, error) {

	// Unmarshal the contents
	ospa := OSPA{}
	err := yaml.Unmarshal(data, &ospa)
	if err != nil {
		log.Error("Failed to parse")
		return ospa, err
	}

	// Check version field
	if err := validVersion(ospa.Version); err != nil {
		return ospa, err
	}

	// Check name field
	if ospa.Name == "" {
		return ospa, errors.New("missing name field")
	}

	// Check client device ID
	if ospa.ClientDeviceID == "" {
		return ospa, errors.New("missing clientDeviceId field")
	}
	if uuid.FromStringOrNil(ospa.ClientDeviceID) == uuid.Nil {
		return ospa, errors.New("clientDeviceId is not a valid UUID")
	}

	// Server port
	if ospa.ServerPort == 0 {
		log.WithField("defaultServerPort", DefaultServerPort).
			Debug("missing serverPort field, using default")
		ospa.ServerPort = DefaultServerPort
	}

	// Echo-IP server
	if ospa.EchoIpServer == "" {
		log.WithField("defaultEchoIpv4Server", ipresolver.DefaultEchoIpV4Server).
			Debug("missing echoIpServer field, using default")
		ospa.EchoIpServer = ipresolver.DefaultEchoIpV4Server
	}

	// Check client's private key
	if ospa.PrivateKeyStr == "" {
		return ospa, errors.New("missing client's private key")
	}

	// Check client's public key
	if ospa.PublicKeyStr == "" {
		return ospa, errors.New("missing client's public key")
	}

	// Check servers's public key
	if ospa.ServerPublicKeyStr == "" {
		return ospa, errors.New("missing servers's public key")
	}

	return ospa, nil
}

// Returns error if the file version is not supported by this program
func validVersion(ver string) error {
	if ver == "" {
		return errors.New("no version specified")
	}

	r, _ := regexp.Compile("^(\\d+).(\\d+).(\\d+)$")

	verNumbering := r.FindStringSubmatch(ver)
	if len(verNumbering) != 3+1 { // + 1 because the first element is the original string
		return errors.New("OSPA file does not contain major.minor.bugfix version format")
	}

	fileVersionMajor, _ := strconv.Atoi(verNumbering[1])
	fileVersionMinor, _ := strconv.Atoi(verNumbering[2])
	//fileVersionBugfix, _ := strconv.Atoi(verNumbering[3])

	if fileVersionMajor != client.VersionMajor {
		log.WithFields(log.Fields{"fileVersionMajor": fileVersionMajor, "supportedVersionMajor": client.VersionMajor}).
			Error("OSPA file version is incompatible with this tool, major version mismatch")
		return errors.New("major version mismatch")
	}
	if fileVersionMinor < client.VersionMinor {
		log.WithFields(log.Fields{"fileVersionMinor": fileVersionMinor, "supportedVersionMinor": client.VersionMinor}).
			Error("OSPA file version is incompatible with this tool, minor version is greater than this tool supports")
		return errors.New("minor version is greater than this tool supports")
	}

	return nil
}
