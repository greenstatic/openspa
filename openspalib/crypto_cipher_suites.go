package openspalib

import (
	"crypto/rsa"
	"errors"
)

type RSA_AES_128_CBC_With_RSA_SHA256 struct {
	ServerPubKey *rsa.PublicKey
	ClientPrivKey *rsa.PrivateKey
}

func (r *RSA_AES_128_CBC_With_RSA_SHA256) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if r.ServerPubKey == nil {
		return nil, errors.New("missing server public key")
	}

	ciphertext, err = encryptWithRSAWithAES256CBC(plaintext, r.ServerPubKey)
	return
}

func (r *RSA_AES_128_CBC_With_RSA_SHA256) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	// TODO - add AES
	return rsaDecrypt(ciphertext, r.ClientPrivKey)
}

func (r *RSA_AES_128_CBC_With_RSA_SHA256) Sign(data []byte) (signature []byte, err error) {
	if r.ClientPrivKey == nil {
		return nil, errors.New("missing client private key")
	}

	signature, err = rsaSha256Signature(data, r.ClientPrivKey)
	return
}

func (r *RSA_AES_128_CBC_With_RSA_SHA256) Verify(text, signature []byte) (valid bool, err error) {
	// TODO
	return
}

func (r *RSA_AES_128_CBC_With_RSA_SHA256) CipherSuiteId () CipherSuiteId {
	return CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256
}

