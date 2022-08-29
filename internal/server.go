package internal

import (
	crypt "crypto"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

func NewServerCipherSuite(c ServerConfigCrypto) (crypto.CipherSuite, error) {
	privKey, err := rsaPrivateKeyFromFile(c.RSA.Server.PrivateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "private key read")
	}

	l := NewPublicKeyLookupDir(c.RSA.Client.PublicKeyLookupDir)
	resolve := NewPublicKeyResolveFromClientUUID(l)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(privKey, resolve)
	return cs, nil
}

var _ crypto.PublicKeyResolver = PublicKeyResolveFromClientUUID{}

type PublicKeyResolveFromClientUUID struct {
	l crypto.PublicKeyLookuper
}

func NewPublicKeyResolveFromClientUUID(l crypto.PublicKeyLookuper) *PublicKeyResolveFromClientUUID {
	p := &PublicKeyResolveFromClientUUID{
		l: l,
	}
	return p
}

func (p PublicKeyResolveFromClientUUID) PublicKey(packet tlv.Container) (crypt.PublicKey, error) {
	uuid, err := openspalib.ClientUUIDFromContainer(packet)
	if err != nil {
		return nil, errors.Wrap(err, "client uuid from container")
	}

	pub, err := p.l.LookupPublicKey(uuid)
	if err != nil {
		return nil, errors.Wrap(err, "lookup public key")
	}

	return pub, nil
}

var _ crypto.PublicKeyLookuper = PublicKeyLookupDir{}

type PublicKeyLookupDir struct {
	DirPath string
}

func NewPublicKeyLookupDir(dirPath string) *PublicKeyLookupDir {
	p := &PublicKeyLookupDir{
		DirPath: dirPath,
	}
	return p
}

func (p PublicKeyLookupDir) LookupPublicKey(clientUUID string) (crypt.PublicKey, error) {
	de, err := os.ReadDir(p.DirPath)
	if err != nil {
		return nil, errors.Wrap(err, "read public key lookup dir")
	}

	for _, e := range de {
		if name := e.Name(); !e.IsDir() && p.clientFilenameMatch(clientUUID, name) {
			b, err := os.ReadFile(filepath.Join(p.DirPath, name))
			if err != nil {
				return nil, errors.Wrap(err, "client key file read")
			}

			pub, err := crypto.RSADecodePublicKey(string(b))
			if err != nil {
				return nil, errors.Wrap(err, "rsa decode client key")
			}

			return pub, nil
		}
	}

	return nil, errors.New("no key found")
}

func (p PublicKeyLookupDir) clientFilenameMatch(clientUUID, filename string) bool {
	if clientUUID == filename {
		return true
	}

	fx := strings.Split(filename, ".")
	if len(fx) > 1 {
		fx = fx[:len(fx)-1]
	}

	return strings.Join(fx, ".") == clientUUID
}

func rsaPrivateKeyFromFile(privateKeyPath string) (*rsa.PrivateKey, error) {
	content, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "read file")
	}

	key, err := crypto.RSADecodePrivateKey(string(content))
	if err != nil {
		return nil, errors.Wrap(err, "rsa decode private key")
	}

	return key, nil
}

//nolint:unused
func rsaPublicKeyFromFile(publicKeyPath string) (*rsa.PublicKey, error) {
	content, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "read file")
	}

	key, err := crypto.RSADecodePublicKey(string(content))
	if err != nil {
		return nil, errors.Wrap(err, "rsa decode public key")
	}

	return key, nil
}
