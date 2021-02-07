package genOspa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/greenstatic/openspa/internal/client"
	"github.com/greenstatic/openspa/internal/ospa"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Encodes the RSA private key to a PEM formatted byte slice
func EncodeRSAPrivateKey(privKey *rsa.PrivateKey) ([]byte, error) {
	// convert private key from DER to PEM
	privKeyPEM := pem.Block{
		"RSA PRIVATE KEY",
		nil,
		x509.MarshalPKCS1PrivateKey(privKey),
	}

	var buf bytes.Buffer

	if err := pem.Encode(&buf, &privKeyPEM); err != nil {
		log.Error("Failed to convert private key to PEM format")
		log.Error(err)
		return nil, err
	}

	return buf.Bytes(), nil
}

// Encodes the RSA public key to a PEM formatted byte slice
func EncodeRSAPublicKey(pubKey *rsa.PublicKey) ([]byte, error) {
	// convert public key from DER to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Error("Failed to extract public key to DER format")
		log.Error(err)
		return nil, err
	}

	// convert public key from DER to PEM
	pubKeyPEM := pem.Block{
		"PUBLIC KEY",
		nil,
		pubKeyBytes,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pubKeyPEM); err != nil {
		log.Error("Failed to convert public key to PEM format")
		log.Error(err)
		return nil, err
	}

	return buf.Bytes(), nil
}

// Generates the OSPA YAML file
func (fileParam *OSPAFileParameters) Generate() ([]byte, error) {

	// Client private key
	privateKeyByte, err := EncodeRSAPrivateKey(fileParam.PrivateKey)
	if err != nil {
		return nil, err
	}
	privateKeyStr := string(privateKeyByte)

	// Client public key
	publicKeyByte, err := EncodeRSAPublicKey(fileParam.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKeyStr := string(publicKeyByte)

	// Server private key
	serverPublicKeyByte, err := EncodeRSAPublicKey(fileParam.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	serverPublicKeyStr := string(serverPublicKeyByte)

	o := ospa.OSPA{
		client.Version,
		fileParam.ConfigName,
		fileParam.ClientDeviceID,
		fileParam.ServerIP,
		fileParam.ServerPort,
		fileParam.EchoIPServer,
		privateKeyStr,
		publicKeyStr,
		serverPublicKeyStr,
	}

	return yaml.Marshal(&o)
}
