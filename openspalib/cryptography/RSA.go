package cryptography

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Creates a signature by hashing the data using SHA-256 then using the
// private RSA key to sign the message.
func RSA_SHA256_signature(data []byte, privKey *rsa.PrivateKey) (signature []byte, err error) {
	// Sign the header and the unsigned body slice
	// Inspired by: https://golang.org/pkg/crypto/rsa/#example_SignPKCS1v15

	if len(data) == 0 {
		return nil, errors.New("cannot sign empty data slice")
	}

	rng := rand.Reader
	hashed := sha256.Sum256(data)
	signature, err = rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])

	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to sign. Error: %s", err))
	}

	return
}

// Verifies a signature by hashing the data using SHA-256 then using the
// public RSA key to check if the message was signed with the corresponding
// private RSA key (this function is meant to be used in conjunction with
// RSA_SHA256_signature(). Please do not call this function with an empty
// data/signature slice, because the response is undefined.
func RSA_SHA256_signature_verify(data []byte, pubKey *rsa.PublicKey, signature []byte) (success bool) {
	// Inspired by: https://golang.org/pkg/crypto/rsa/#VerifyPKCS1v15

	// IDEA - could check if data slice is empty and return an error.

	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)

	if err != nil {
		// signature does not match
		return false
	}

	return true

}

// Using a RSA public key we encrypt a slice of byte data.
func RSA_encrypt(data []byte, pubKey *rsa.PublicKey) (ciphertext []byte, err error) {

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

// Using the RSA private key we decrypt a slice of byte data that
// was encrypted using the corresponding RSA public key.
func RSA_decrypt(data []byte, privKey *rsa.PrivateKey) (plaintext []byte, err error) {

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
