package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

type RSAEncrypter struct {
	pubkey *rsa.PublicKey
}

func NewRSAEncrypter(pubkey *rsa.PublicKey) *RSAEncrypter {
	r := &RSAEncrypter{
		pubkey: pubkey,
	}
	return r
}

func (r *RSAEncrypter) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if len(plaintext) == 0 {
		return nil, errors.New("cannot encrypt empty byte slice")
	}

	ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, r.pubkey, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

type RSADecrypter struct {
	privkey *rsa.PrivateKey
}

func NewRSADecrypter(privkey *rsa.PrivateKey) *RSADecrypter {
	r := &RSADecrypter{
		privkey: privkey,
	}
	return r
}

func (r *RSADecrypter) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("cannot decrypt empty byte slice")
	}

	plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, r.privkey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

//nolint:revive,stylecheck
type RSA_SHA256Signer struct {
	privkey *rsa.PrivateKey
}

//nolint:revive,stylecheck
func NewRSA_SHA256Signer(privkey *rsa.PrivateKey) *RSA_SHA256Signer {
	r := &RSA_SHA256Signer{
		privkey: privkey,
	}
	return r
}

func (r *RSA_SHA256Signer) Sign(data []byte) (signature []byte, err error) {
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

//nolint:revive,stylecheck
type RSA_SHA256SignatureVerifier struct {
	pubkey *rsa.PublicKey
}

//nolint:revive,stylecheck
func NewRSA_SHA256SignatureVerifier(pubkey *rsa.PublicKey) *RSA_SHA256SignatureVerifier {
	r := &RSA_SHA256SignatureVerifier{
		pubkey: pubkey,
	}
	return r
}

func (r *RSA_SHA256SignatureVerifier) Verify(text, signature []byte) (valid bool, err error) {
	hashed := sha256.Sum256(text)
	err = rsa.VerifyPKCS1v15(r.pubkey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func RSAKeypair(bitSize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := key.Public().(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("type assertion failed")
	}

	return key, pub, nil
}

func RSAEncodePrivateKey(key *rsa.PrivateKey) (string, error) {
	p := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &p); err != nil {
		return "", errors.Wrap(err, "pem encode")
	}

	return buf.String(), nil
}

func RSAEncodePublicKey(key *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", errors.Wrap(err, "extract key to DER format")
	}

	p := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &p); err != nil {
		return "", errors.Wrap(err, "pem encode")
	}

	return buf.String(), nil
}

func RSADecodePrivateKey(key string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("pem decode")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("header is not RSA PRIVATE KEY")
	}

	pub, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse pkcs1 private key")
	}

	return pub, nil
}

func RSADecodePublicKey(key string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))

	if block == nil {
		return nil, errors.New("pem decode")
	}

	if block.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "x509 parse pkix public key")
		}

		switch pub := pub.(type) {
		case *rsa.PublicKey:
			return pub, nil // This is what we are after

		// case *dsa.PublicKey:
		//	return nil, errors.New("dsa public key")

		case *ecdsa.PublicKey:
			return nil, errors.New("ecdsa public key")
		}

		return nil, errors.New("unknown public key")
	}

	if block.Type == "RSA PUBLIC KEY" {
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "x509 parse pkcs1 public key")
		}

		return pub, nil
	}

	return nil, errors.New("decode error")
}
