package crypto

import (
	"errors"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
)

type CipherSuiteId uint8

const (
	CipherUnknown                 CipherSuiteId = 0   // only to be used for development
	CipherNoSecurity              CipherSuiteId = 255 // only to be used for development
	CipherRSA_SHA256_AES256CBC_ID CipherSuiteId = 1
)

type CipherSuite interface {
	CipherSuiteId() CipherSuiteId

	// Secure performs Encryption (body) and SignatureSignor (header+body) and returns an Encrypted TLV container
	Secure(header []byte, packet tlv.Container) (tlv.Container, error)

	// Unlock performs Decryption and SignatureSignor verification and returns the Packet TLV container that was secured
	Unlock(header []byte, ec tlv.Container) (tlv.Container, error)
}

type Encryption interface {
	Encrypter
	Decrypter
}

type Signature interface {
	SignatureSignor
	SignatureVerifier
}

type Encrypter interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
}

type Decrypter interface {
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type SignatureSignor interface {
	Sign(data []byte) (signature []byte, err error)
}

type SignatureVerifier interface {
	Verify(text, signature []byte) (valid bool, err error)
}

func CipherSuiteStringToId(s string) CipherSuiteId {
	switch s {
	case "CipherNoSecurity":
		return CipherNoSecurity
	case "CipherSuite_RSA_SHA256_AES256CBC":
		return CipherRSA_SHA256_AES256CBC_ID
	default:
		return CipherUnknown
	}
}

func CipherSuiteIdToString(c CipherSuiteId) (string, error) {
	switch c {
	case CipherNoSecurity:
		return "CipherNoSecurity", nil
	case CipherRSA_SHA256_AES256CBC_ID:
		return "CipherSuite_RSA_SHA256_AES256CBC", nil
	}

	return "", errors.New("unsupported cipher suite id")
}

func MustCipherSuiteIdToString(c CipherSuiteId) string {
	s, err := CipherSuiteIdToString(c)
	if err != nil {
		panic(err)
	}
	return s
}
