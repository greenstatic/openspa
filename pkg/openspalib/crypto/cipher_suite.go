package crypto

import (
	"errors"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
)

type CipherSuiteID uint8

//nolint:revive,stylecheck
const (
	CipherUnknown                 CipherSuiteID = 0   // only to be used for development
	CipherNoSecurity              CipherSuiteID = 255 // only to be used for development
	CipherRSA_SHA256_AES256CBC_ID CipherSuiteID = 1
)

type CipherSuite interface {
	CipherSuiteID() CipherSuiteID

	// Secure performs Encryption (body) and SignatureSignor (header+body) and returns an Encrypted TLV container.
	// The meta parameter is additional information that is available for security, it is not actually sent to the
	// recipient.
	Secure(header []byte, packet, meta tlv.Container) (tlv.Container, error)

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

func CipherSuiteStringToID(s string) CipherSuiteID {
	switch s {
	case "CipherSuite_NoSecurity":
		return CipherNoSecurity
	case "CipherSuite_RSA_SHA256_AES256CBC":
		return CipherRSA_SHA256_AES256CBC_ID
	default:
		return CipherUnknown
	}
}

func CipherSuiteIDToString(c CipherSuiteID) (string, error) {
	switch c {
	case CipherNoSecurity:
		return "CipherSuite_NoSecurity", nil
	case CipherRSA_SHA256_AES256CBC_ID:
		return "CipherSuite_RSA_SHA256_AES256CBC", nil
	case CipherUnknown:
		return "", errors.New("unknown cipher suite id")
	default:
		return "", errors.New("unsupported cipher suite id")
	}
}

func MustCipherSuiteIDToString(c CipherSuiteID) string {
	s, err := CipherSuiteIDToString(c)
	if err != nil {
		panic(err)
	}
	return s
}
