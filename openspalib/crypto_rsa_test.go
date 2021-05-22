package openspalib

import (
	"bytes"
	"testing"
)

// Tests the following functions:
// * rsaEncrypt()
// * rsaDecrypt()
func TestRSAEncryptAndDecrypt(t *testing.T) {
	tests := []struct {
		inputData   []byte
		expectedErr bool
		onErrorStr  string
	}{
		{
			[]byte{0x74, 0x65, 0x73, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x20, 0x70, 0x61,
				0x69, 0x6E},
			false,
			"failed to encrypt/decrypt data with completely valid function calls",
		},
		{
			[]byte{0x74},
			false,
			"failed to encrypt/decrypt data with completely valid function calls",
		},
		{
			[]byte{},
			true,
			"failed to return error when input data slice is empty",
		},
	}

	for i, test := range tests {
		ciphertext, err := rsaEncrypt(test.inputData, &test2048Key.PublicKey)

		if err != nil != test.expectedErr {
			t.Errorf("Unexpected error while encrypting for test case: %d, err: %s, reason: %s",
				i, err, test.onErrorStr)
			continue
		}

		if test.expectedErr {
			continue
		}

		plaintext, err := rsaDecrypt(ciphertext, test2048Key)

		if err != nil != test.expectedErr {
			t.Errorf("Unexpected error while decrypting for test case: %d, err: %s, reason %s",
				i, err, test.onErrorStr)
		}

		if !bytes.Equal(plaintext, test.inputData) {
			t.Errorf("Decrypted content after encryption is not the same as the initial encrypted content for test case: %d, reason: %s",
				i, test.onErrorStr)
		}
	}
}
