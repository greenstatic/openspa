package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/pkg/errors"
)

func AES256CBCEncrypt(plaintext []byte) (ciphertext, iv, key []byte, err error) {
	iv = make([]byte, 16)
	if _, err2 := rand.Read(iv); err2 != nil {
		err = errors.Wrap(err2, "random iv generation")
	}

	key = make([]byte, 32)
	if _, err2 := rand.Read(key); err2 != nil {
		err = errors.Wrap(err2, "random key generation")
	}

	e := NewAES256CBCEncrypter(iv, key)
	ciphertext, err = e.Encrypt(plaintext)
	return
}

var _ Encrypter = AES256CBCEncrypter{}

type AES256CBCEncrypter struct {
	iv  []byte
	key []byte
}

func NewAES256CBCEncrypter(iv, key []byte) *AES256CBCEncrypter {
	a := &AES256CBCEncrypter{
		iv:  iv,
		key: key,
	}
	return a
}

func (a AES256CBCEncrypter) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	return aes256CBCEncrypt(plaintext, a.key, a.iv)
}

func aes256CBCEncrypt(plaintext, key, iv []byte) (ciphertext []byte, err error) {
	// Pad the data
	dataPadded, err := PaddingPKCS7(plaintext, aes.BlockSize)
	if err != nil {
		return nil, errors.Wrap(err, "padding pkcs7")
	}

	return _aes256CBCEncrypt(dataPadded, key, iv)
}

func _aes256CBCEncrypt(plaintext, key, iv []byte) (ciphertext []byte, err error) {
	const ivSize = aes.BlockSize

	// check just to be sure that the plaintext body is a multiple of the AES block size
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext not a multiple of the block size")
	}

	if len(iv) != ivSize {
		return nil, errors.New("invalid IV size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	c := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(c, plaintext)

	return c, nil
}

var _ Decrypter = AES256CBCDecrypter{}

type AES256CBCDecrypter struct {
	iv  []byte
	key []byte
}

func NewAES256CBCDecrypter(iv, key []byte) *AES256CBCDecrypter {
	a := &AES256CBCDecrypter{
		iv:  iv,
		key: key,
	}
	return a
}

func (a AES256CBCDecrypter) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	return aes256CBCDecrypt(ciphertext, a.iv, a.key)
}

func aes256CBCDecrypt(ciphertext, iv, key []byte) (plaintext []byte, err error) {
	padded, err := _aes256CBCDecrypt(ciphertext, iv, key)
	if err != nil {
		return nil, errors.Wrap(err, "aes256cbc decrypt")
	}

	plaintext, err = PaddingPKCS7Remove(padded, aes.BlockSize)
	if err != nil {
		return nil, errors.Wrap(err, "remove pkcs7 padding")
	}

	return plaintext, nil
}

func _aes256CBCDecrypt(ciphertext, iv, key []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("tried to decrypt using AES-256-CBC ciphertext that is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext) // will decrypt in-place

	return plaintext, nil
}
