package openspalib

type Container interface {
	GetByte(key uint8) (b byte, exists bool)
	GetBytes(key uint8) (b []byte, exists bool)

	SetByte(key uint8, value byte)
	SetBytes(key uint8, value []byte)

	Remove(key uint8)

	Bytes() []byte

	// Size returns the length of the byte slice or buffer
	Size() int

	// NoEntries returns the number of nodes in the container
	NoEntries() int

	// Merge merges the input parameter container with the container on which it is called and returns the merged
	// container. All data is copied, no modifications are made to either input containers.
	// TODO - ?
	//Merge(c Container) (Container, error)
}

type CipherSuite interface {
	// Secure performs Encryption and Signature on the plaintext and returns the cipertext+signature
	Secure(plaintext []byte) ([]byte, error)

	// Unlock performs Decryption and Signature verification and returns the plaintext
	Unlock(ciphertext []byte) ([]byte, error)

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
