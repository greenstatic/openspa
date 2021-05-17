package openspalib

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/pkg/errors"
)

// Using a RSA public key we encrypt a slice of byte data.
func rsaEncrypt(data []byte, pubKey *rsa.PublicKey) (ciphertext []byte, err error) {

	if len(data) == 0 {
		return nil, errors.New("cannot encrypt empty data slice")
	}

	ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)

	if err != nil {
		// failed to encrypt the plaintext using the public RSA key
		return nil, err
	}

	return
}

// Using the RSA private key we decrypt a slice of byte data that was encrypted using the corresponding RSA public key.
func rsaDecrypt(data []byte, privKey *rsa.PrivateKey) (plaintext []byte, err error) {

	if len(data) == 0 {
		return nil, errors.New("cannot decrypt empty data slice")
	}

	plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, data)

	if err != nil {
		// failed to decrypt the ciphertext using the private RSA key
		return nil, err
	}

	return
}
