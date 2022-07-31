package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RSA2048Encrypter struct {
	pubkey *rsa.PublicKey
}

func NewRSA2048Encrypter(pubkey *rsa.PublicKey) *RSA2048Encrypter {
	r := &RSA2048Encrypter{
		pubkey: pubkey,
	}
	return r
}

func (r *RSA2048Encrypter) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot encrypt empty byte slice")
	}

	ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, r.pubkey, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

type RSA2048Decrypter struct {
	privkey *rsa.PrivateKey
}

func NewRSA2048Decrypter(privkey *rsa.PrivateKey) *RSA2048Decrypter {
	r := &RSA2048Decrypter{
		privkey: privkey,
	}
	return r
}

func (r *RSA2048Decrypter) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("cannot decrypt empty byte slice")
	}

	plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, r.privkey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

type RSA2048_SHA256Signer struct {
	privkey *rsa.PrivateKey
}

func NewRSA2048_SHA256Signer(privkey *rsa.PrivateKey) *RSA2048_SHA256Signer {
	r := &RSA2048_SHA256Signer{
		privkey: privkey,
	}
	return r
}

func (r *RSA2048_SHA256Signer) Sign(data []byte) (signature []byte, err error) {
	if len(data) == 0 {
		return nil, errors.New("cannot sign empty byte slice")
	}

	hash := sha256.Sum256(data)
	signature, err = rsa.SignPKCS1v15(rand.Reader, r.privkey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type RSA2048_SHA256SignatureVerifier struct {
	pubkey *rsa.PublicKey
}

func NewRSA2048_SHA256SignatureVerifier(pubkey *rsa.PublicKey) *RSA2048_SHA256SignatureVerifier {
	r := &RSA2048_SHA256SignatureVerifier{
		pubkey: pubkey,
	}
	return r
}

func (r *RSA2048_SHA256SignatureVerifier) Verify(text, signature []byte) (valid bool, err error) {
	hashed := sha256.Sum256(text)
	err = rsa.VerifyPKCS1v15(r.pubkey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, err
	}

	return true, nil
}
