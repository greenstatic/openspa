package internal

import (
	"io/ioutil"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	uuid "github.com/satori/go.uuid"
	"gopkg.in/yaml.v2"
)

const OSPAFileVersion = "0.2"

type OSPA struct {
	Version    string     `yaml:"version"`
	ClientUUID string     `yaml:"clientUUID"`
	ServerHost string     `yaml:"serverHost"`
	ServerPort int        `yaml:"serverPort"`
	Crypto     OSPACrypto `yaml:"crypto"`
}

type OSPACrypto struct {
	CipherSuitePriority []string      `yaml:"cipherSuitePriority"`
	RSA                 OSPACryptoRSA `yaml:"rsa"`
}

type OSPACryptoRSA struct {
	Client OSPACryptoRSAClient `yaml:"client"`
	Server OSPACryptoRSAServer `yaml:"server"`
}

type OSPACryptoRSAClient struct {
	PrivateKey string `yaml:"privateKey"`
	PublicKey  string `yaml:"publicKey"`
}

type OSPACryptoRSAServer struct {
	PublicKey string `yaml:"publicKey"`
}

func OSPAFromFile(path string) (OSPA, error) {
	log.Debug().Msgf("Reading OSPA file: %s", path)
	return ospaFromFile(path)
}

func ospaFromFile(path string) (OSPA, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return OSPA{}, errors.Wrap(err, "file read")
	}

	return OSPAParse(b)
}

func OSPAParse(b []byte) (OSPA, error) {
	o := OSPA{}
	if err := yaml.Unmarshal(b, &o); err != nil {
		return OSPA{}, errors.Wrap(err, "yaml unmarshal")
	}
	return o, nil
}

func (o OSPA) Verify() error {
	if o.Version != OSPAFileVersion {
		return errors.New("unsupported file version")
	}

	_, err := uuid.FromString(o.ClientUUID)
	if err != nil {
		return errors.New("clientUUID invalid UUID")
	}

	if len(o.ServerHost) == 0 {
		return errors.New("server host invalid")
	}

	if !(o.ServerPort > 0 && o.ServerPort < 65535) {
		return errors.New("server port invalid")
	}

	if err := o.Crypto.Verify(); err != nil {
		return errors.Wrap(err, "crypto")
	}

	return nil
}

func (o OSPACrypto) Verify() error {
	if len(o.CipherSuitePriority) == 0 {
		return errors.New("cipherSuitePriority empty")
	}

	for _, cs := range o.CipherSuitePriority {
		if crypto.CipherSuiteStringToId(cs) == crypto.CipherUnknown {
			return errors.New("cipherSuitePriority unsupported/unknown cipher: " + cs)
		}
	}

	if err := o.RSA.Verify(); err != nil {
		return errors.Wrap(err, "rsa")
	}

	return nil
}

func (o OSPACryptoRSA) Verify() error {
	if err := o.Client.Verify(); err != nil {
		return errors.Wrap(err, "client")
	}
	if err := o.Server.Verify(); err != nil {
		return errors.Wrap(err, "server")
	}
	return nil
}

func (o OSPACryptoRSAClient) Verify() error {
	if len(o.PrivateKey) < 512 {
		return errors.New("private key empty or too short")
	}
	if len(o.PublicKey) < 512 {
		return errors.New("public key empty or too short")
	}
	return nil
}

func (o OSPACryptoRSAServer) Verify() error {
	if len(o.PublicKey) < 512 {
		return errors.New("public key empty or too short")
	}
	return nil
}
