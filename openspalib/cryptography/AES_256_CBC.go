package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypts the plaintext using the key with AES 256 bit CBC encryption.
// Beware, this function WILL NOT pad any data, if the plaintext is not
// a multiple of the block size (16 bytes) we will return an error.
// We will however create a random IV (16 bytes) and add it as the prefix
// of the ciphertext.

// Inspired by the example at: https://golang.org/pkg/crypto/cipher/#NewCBCEncrypter
func AES_256_CBC_encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {

	const ivSize = aes.BlockSize

	// check just to be sure that the plaintext body is a multiple of the AES block size
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("tried to encrypt using AES-256-CBC plaintext that is not a multiple of the block size")
	}

	if len(iv) != ivSize {
		return nil, errors.New("tried to encrypt using AES-256-CBC using an invalid IV (not 16 bytes long)")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, ivSize+len(plaintext))
	for i := 0; i < ivSize; i++ {
		ciphertext[i] = iv[i]
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[ivSize:], plaintext)

	return ciphertext, nil
}

// Decrypts the plaintext that was encrypted using AES 256 bit CBC encryption,
// using the key. Beware, this function WILL NOT attempt to remove any padding,
// that is left for the user to do. Note this function assumes that the IV that
// was used to encrypt the plaintext is stored as the prefix of the ciphertext
// (first 16 bytes).

// Inspired by the example at: https://golang.org/pkg/crypto/cipher/#NewCBCDecrypter
func AES_256_CBC_decrypt(ciphertext []byte, key []byte) ([]byte, error) {

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("tried to decrypt using AES-256-CBC ciphertext that is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	// Get the IV from the prefix of the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertextOnly := ciphertext[aes.BlockSize:] // the actual ciphertext without the IV

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertextOnly, ciphertextOnly) // will decrypt in-place

	return ciphertextOnly, nil
}

// Calls AES_256_CBC_encrypt() with a randomly generated IV and appends the PKCS7 corresponding
// padding. See the return value of AES_256_CBC_encrypt().
func AES_256_CBC_encrypt_with_padding(plaintext []byte, key []byte) ([]byte, error) {

	// Pad the data
	paddingSize := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	dataPadded := PaddingPKCS7(plaintext, paddingSize)

	// Generate random IV
	iv, err := AES_256_CBC_RandomIV()
	if err != nil {
		return nil, err
	}

	return AES_256_CBC_encrypt(dataPadded, key, iv)
}

// Calls AES_256_CBC_decrypt() and returns the result without the PKCS7 padding.
func AES_256_CBC_decrypt_with_padding(ciphertext []byte, key []byte) ([]byte, error) {
	plaintextPadded, err := AES_256_CBC_decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	return PaddingPKCS7Remove(plaintextPadded)
}

// Returns a random IV (16 bytes = aes.BlockSize)
func AES_256_CBC_RandomIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}
