package openspalib

import (
	"crypto/rsa"
	"github.com/pkg/errors"
)

// Encrypts the data with AES-256-CBC with a random key and then encrypts the random AES key
// with a RSA public key. The key is then appended as the prefix of the ciphertext.
func encryptWithRSAWithAES256CBC(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	// Generate random AES key
	const aesKeyLength = 32 // 32 bytes = 256 bits
	aesKey, err := randomKey(aesKeyLength)

	if err != nil {
		return nil, err
	}

	// Encrypt using AES-256-CBC with padding
	bodyCiphertext, err := aes256CbcEncryptWithPadding(plaintext, aesKey)

	if err != nil {
		return nil, err
	}

	// Encrypt the AES key using the public key
	aesKeyCiphertext, err := rsaEncrypt(aesKey, pubKey)
	if err != nil {
		// failed to encrypt the AES key using the RSA public key
		return nil, err
	}

	encryptedDataByte := make([]byte, 0, len(aesKeyCiphertext)+len(bodyCiphertext))
	encryptedDataByte = append(encryptedDataByte, aesKeyCiphertext...)
	encryptedDataByte = append(encryptedDataByte, bodyCiphertext...)

	return encryptedDataByte, nil
}

func decryptWithRSAWithAES256CBC(ciphertext []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	// TODO - fix this
	const rsaEncAESKeyLen = 256             // bytes (2048 * 8 = 256)
	if len(ciphertext) <= rsaEncAESKeyLen { // <= because we also need something to decrypt using AES (not just the key)
		return nil, errors.New("ciphertext is too short to be encrypted using RSA 2048 + AES 256 CBC")
	}

	rsaEncAESKey := ciphertext[:rsaEncAESKeyLen]
	bodyCiphertext := ciphertext[rsaEncAESKeyLen:]

	aesKey, err := rsaDecrypt(rsaEncAESKey, privKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aes256CbcDecryptWithPadding(bodyCiphertext, aesKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
