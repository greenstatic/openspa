package cryptography

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// Opens a file and dumps its contents into memory.
// Note: use this function for files which are small
// since we dump the entire file immediately.

// inspired by: https://golang.org/pkg/io/ioutil/#ReadFile
func ReadPEMFile(path string) ([]byte, error) {
	content, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, errors.New("failed to read file: " + err.Error())
	}

	return content, nil
}

// Decodes the PEM contents as a RSA private key and returns
// a pointer to the rsa.PrivateKey.

// A correctly formatted RSA private key PEM file will contain
// the header "-----BEGIN RSA PRIVATE KEY-----" and end with
// "-----END RSA PRIVATE KEY-----". The contents will be the
// base64 encoded RSA private key using ASN.1 binary encoding

// The following OpenSSL command will generate an appropriate
// 2048 bit RSA private key: "openssl genrsa -out my.key 2048".
func DecodeX509PrivateKeyRSA(key []byte) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode(key)

	if block == nil {
		return nil, errors.New("failed to decode contents")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("contents do not describe a RSA private key with the header \"-----BEGIN RSA PRIVATE KEY-----\"")
	}

	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, errors.New("failed to parse DER encoded private key: " + err.Error())
	}

	return pub, nil
}

// Decodes a PEM RSA Public key and returns a pointer to
// the rsa.PublicKey.

// The function accepts two formats of RSA public key encodings.
// The first is the first RSA format invented with the following
// header: "-----BEGIN RSA PUBLIC KEY-----" the second format has
// the following header: "-----BEGIN PUBLIC KEY-----". We will
// refer to these "BEGIN RSA PUBLIC KEY" and "BEGIN PUBLIC KEY"
// respectively.

// If you wish to learn a bit of history/trivia for what are the
// differences, here is a GREAT StackOverflow answer:
// https://stackoverflow.com/a/29707204.

// (NOT RECOMMENDED)
// The following OpenSSL command will extract a "BEGIN RSA PUBLIC KEY"
// formatted RSA public key from an existing RSA private key:
// "openssl rsa -in my.key -pubout -RSAPublicKey_out -out my.pub" - note the
// "-RSAPublicKey_out" flag!

// (RECOMMENDED)
// The following OpenSSL command will extract a "BEGIN PUBLIC KEY"
// formatted RSA public key from an existing RSA private key:
// "openssl rsa -in my.key -pubout -out my.pub"

// The reason why we recommend the "BEGIN PUBLIC KEY" format is because
// it is more common. The "BEGIN RSA PUBLIC KEY" format is only supported
// for compatibility reasons.

// inspired by: https://golang.org/pkg/crypto/x509/#ParsePKIXPublicKey
func DecodeX509PublicKeyRSA(key []byte) (*rsa.PublicKey, error) {

	block, _ := pem.Decode(key)

	if block == nil {
		return nil, errors.New("failed to decode contents")
	}

	// This is the "BEGIN PUBLIC KEY" format
	if block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)

		if err != nil {
			return nil, errors.New("failed to parse DER encoded public key: " + err.Error())
		}

		switch pub := pub.(type) {
		case *rsa.PublicKey:
			return pub, nil // This is what we are after

		case *dsa.PublicKey:
			return nil, errors.New("public key is not a RSA public key but a DSA public key")

		case *ecdsa.PublicKey:
			return nil, errors.New("public key is not a RSA public key but a ECDSA public key")

		default:
			return nil, errors.New("public key is not a RSA public key, we failed to recognize it (it is not DSA or ECDSA)")
		}

	} else if block.Type == "RSA PUBLIC KEY" {
		// This is the "BEGIN RSA PUBLIC KEY" format

		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)

		if err != nil {
			return nil, errors.New("failed to parse DER encoded public key: " + err.Error())
		}

		return pub, nil

	} else {
		return nil, errors.New("contents do not describe a public key with the header \"-----BEGIN PUBLIC KEY-----\" or \"-----BEGIN RSA PUBLIC KEY-----\"")
	}

}
