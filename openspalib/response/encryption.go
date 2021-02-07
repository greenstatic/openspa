package response

import (
	"crypto/rsa"
	"errors"
	"github.com/greenstatic/openspalib/cryptography"
	"github.com/greenstatic/openspalib/header"
)

// Checks if we are allowed to encrypt data. Returns an error if we
// are not, otherwise a lack of error signifies permission to encrypt.
func (p *Packet) canEncrypt() error {
	if len(p.Signature) == 0 {
		return errors.New("packet is without a signature")
	}

	if len(p.ByteData) == 0 {
		return errors.New("packet contains no byte data")
	}

	return nil
}

// Returns the plaintext that we will encrypt.
func (p *Packet) EncryptionPlaintext() ([]byte, error) {

	// Can encrypt?
	if err := p.canEncrypt(); err != nil {
		return nil, err
	}

	payload := p.ByteData[header.Size:]

	plaintext := make([]byte, 0, len(payload)+len(p.Signature))

	plaintext = append(plaintext, payload...)
	plaintext = append(plaintext, p.Signature...)

	return plaintext, nil
}

// Adds encrypted data to the packet.
func (p *Packet) AddEncryptionData(ciphertext []byte) error {

	// Can encrypt?
	if err := p.canEncrypt(); err != nil {
		return err
	}

	p.Encrypted = ciphertext
	return nil
}

// Encrypts the byte data using 2048 bit RSA with AES 256-bit CBC mode and adds it to the
// packet.
func (p *Packet) Encrypt_RSA_2048_With_AES_256_CBC(pubKey *rsa.PublicKey) error {

	plaintext, err := p.EncryptionPlaintext()
	if err != nil {
		return err
	}

	ciphertext, err := cryptography.EncryptWithRSA_2048_with_AES_256_CBC(plaintext, pubKey)

	if err != nil {
		return err
	}

	p.AddEncryptionData(ciphertext)
	return nil
}
