package openspalib

import (
	"crypto/rand"
	"fmt"
	"github.com/pkg/errors"
)

const (
	nonceSize = 3 // bytes - according to the OpenSPA protocol
)

type Nonce []byte

func RandomNonce() (Nonce, error) {
	nonce := make([]byte, nonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		return Nonce{}, errors.Wrap(err, "generating random nonce")
	}

	return nonce, nil
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

type EncryptionMethodImps []EncryptionMethodImp

type EncryptionMethodImp interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}

type encryptionMethodMock struct{}

func (_ encryptionMethodMock) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	ciphertext = plaintext
	return
}

func (_ encryptionMethodMock) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	plaintext = ciphertext
	return
}
