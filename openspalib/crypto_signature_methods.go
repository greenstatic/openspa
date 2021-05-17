package openspalib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/pkg/errors"
)

const (
	SignatureMethod_RSA_SHA256 = 0x01
)

type SignatureMethod uint8

func (s *SignatureMethod) ToBin() byte {
	return uint8(*s)
}

// SignatureMethodIsSupported returns true if the input SignatureMethod is supported.
func SignatureMethodIsSupported(s SignatureMethod) bool {
	return s == SignatureMethod_RSA_SHA256
}

// SignatureMethodSupport returns a slice of SignatureMethod that are supported.
func SignatureMethodSupport() []SignatureMethod {
	return []SignatureMethod{
		SignatureMethod_RSA_SHA256,
	}
}

// Creates a signature by hashing the data using SHA-256 then using the private RSA key to sign the message.
func rsaSha256Signature(data []byte, privKey *rsa.PrivateKey) (signature []byte, err error) {
	// Sign the header and the unsigned body slice
	// Inspired by: https://golang.org/pkg/crypto/rsa/#example_SignPKCS1v15

	if len(data) == 0 {
		return nil, errors.New("cannot sign empty data slice")
	}

	rng := rand.Reader
	hashed := sha256.Sum256(data)
	signature, err = rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])

	if err != nil {
		return nil, fmt.Errorf("failed to sign. Error: %s", err)
	}

	return
}

// Verifies a signature by hashing the data using SHA-256 then using the public RSA key to check if the message was
// signed with the corresponding private RSA key (this function is meant to be used in conjunction with
// rsaSha256Signature(). Please do not call this function with an empty data/signature slice, because the response is
// undefined.
func rsaSha256SignatureVerify(data []byte, pubKey *rsa.PublicKey, signature []byte) (success bool) {
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
