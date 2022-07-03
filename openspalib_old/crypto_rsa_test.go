package openspalib_old

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestTestingRsaKeyPair(t *testing.T) {
	tests := []struct {
		f func() (*rsa.PrivateKey, *rsa.PublicKey)
	}{
		// Test case: 1
		{
			f: TestingRsaKeyPair1,
		},
		// Test case: 2
		{
			f: TestingRsaKeyPair2,
		},
	}

	for i, test := range tests {
		testNo := i + 1

		priv, pub := test.f()

		text := "here be dragons"

		encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(text))
		if err != nil {
			t.Fatalf("Test case: %d failed to encrypt test string, err: %v", testNo, err)
		}

		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encrypted)
		if err != nil {
			t.Fatalf("Test case: %d failed to decrypt test string, err: %v", testNo, err)
		}

		decryptedStr := string(decrypted)
		if text != decryptedStr {
			t.Errorf("Test case: %d Text does not match, %s != %s", testNo, text, decryptedStr)
		}
	}

}

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
