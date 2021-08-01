package openspalib

import (
	"crypto/rand"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"strings"
)

const (
	nonceSize = 3 // bytes - according to the OpenSPA protocol

	CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256 = CipherSuiteId(0x1)

	// CipherSuite_Mock - DO NOT USE IN PRODUCTION! No cipher operations will be performed (i.e. no encryption & signing)
	CipherSuite_Mock = CipherSuiteId(0x0)
)

type Nonce []byte
type CipherSuiteId uint8

type CipherSuite interface {
	CryptoEncryptionMethod
	CryptoDecryptionMethod
	CryptoSignatureMethod
	CryptoSignatureVerificationMethod
	CipherSuiteId() CipherSuiteId
}

type CryptoEncryptionMethod interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
}

type CryptoDecryptionMethod interface {
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type CryptoSignatureMethod interface {
	Sign(data []byte) (signature []byte, err error)
}

type CryptoSignatureVerificationMethod interface {
	Verify(text, signature []byte) (valid bool, err error)
}

func (c CipherSuiteId) Bin() byte {
	return byte(c)
}

// CryptoMethodMock DO NOT USE THIS IN PRODUCTION!!! This mocks all cryptographic operations and does not encrypt/sign
// anything. This is only to be used for development testing.
type CryptoMethodMock struct{}

func RandomNonce() (Nonce, error) {
	nonce := make([]byte, nonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return Nonce{}, errors.Wrap(err, "generating random nonce")
	}

	return nonce, nil
}

// CipherSuiteIsSupported returns true if the input CipherSuiteId is supported.
func CipherSuiteIsSupported(c CipherSuiteId) bool {
	s := CipherSuiteSupport()
	for _, i := range s {
		if i == c {
			return true
		}
	}

	return false
}

// CipherSuiteSupport returns a slice of all CipherSuiteId that are supported. If the OS env variable
// `OSPA_CIPHER_SUITE_MOCK` is defined and set to "true" (case-insensitive), CipherSuite_Mock will be added to the slice
// of supported cipher suites.
func CipherSuiteSupport() []CipherSuiteId {
	mockAllowed := false
	if strings.ToLower(os.Getenv("OSPA_CIPHER_SUITE_MOCK")) == "true" {
		mockAllowed = true
	}

	return cipherSuiteSupport(mockAllowed)
}

// CipherSuiteSupport returns a slice of all CipherSuiteId that are supported. If mockAllowed is true, CipherSuite_Mock
// will be added to the slice of supported cipher suites.
func cipherSuiteSupport(mockAllowed bool) []CipherSuiteId {
	s := []CipherSuiteId{
		CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
	}

	if mockAllowed {
		s = append(s, CipherSuite_Mock)
	}

	return s
}


func (_ CryptoMethodMock) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	ciphertext = plaintext
	return
}

func (_ CryptoMethodMock) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	plaintext = ciphertext
	return
}

func (_ CryptoMethodMock) Sign(text []byte) (signature []byte, err error) {
	signature = []byte{0x0, 0x1, 0x2, 0x3}
	err = nil
	return
}

func (_ CryptoMethodMock) Verify(text, signature []byte) (valid bool, err error) {
	return true, nil
}

func (_ CryptoMethodMock) CipherSuiteId() CipherSuiteId {
	return CipherSuiteId(0x1) // Pretend to be
}

// Generate a cryptographically secure pseudorandom key. Size parameter should by in bytes.
func randomKey(size uint) ([]byte, error) {
	if size == 0 {
		return nil, errors.New("size must be larger than 0")
	}

	randKey := make([]byte, size)
	_, err := rand.Read(randKey)

	if err != nil {
		return nil, fmt.Errorf("failed to generate a cryptographically secure pseudorandom key size: %d", size)
	}

	return randKey, nil
}

// Returns the data with padding added to the end following the PKCS#7 (RFC 5652) guidelines.
func paddingPKCS7(data []byte, size int) []byte {
	// Create a padded slice
	padding := make([]byte, size, size)

	for i := 0; i < size; i++ {
		padding[i] = byte(size)
	}

	// Create the final data with the padding slice
	dataPadded := make([]byte, 0, len(data)+size)

	dataPadded = append(dataPadded, data...)
	dataPadded = append(dataPadded, padding...)

	return dataPadded
}

// Returns the data with the padding removed at the end following the PKCS#7 (RFC 5652) guidelines. Reverses what
// paddingPKCS7 does.
func paddingPKCS7Remove(data []byte) ([]byte, error) {
	size := int(data[len(data)-1])

	// In case the calculated size is larger than the data slice return error
	if len(data) < size {
		return nil, errors.New("calculated padded size is larger than data slice")
	}

	return data[:len(data)-size], nil
}
