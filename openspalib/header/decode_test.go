package header

import (
	"testing"
)

// Tests for the func binaryDecode
func TestBinaryDecode(t *testing.T) {

	tests := []struct {
		inputData      []byte
		expectedErr    bool
		expectedResult Header
		onErrorStr     string
	}{
		{
			[]byte{0x10, 0x01},
			false,
			Header{1, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"fails to work with an input of two bytes for version 1, request packet type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x18, 0x01},
			false,
			Header{1, false, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"fails to work with an input of two bytes for version 1, response packet type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x10, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			false,
			Header{1, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"fails to work with a larger than two byte input for version 1, request packet type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x10},
			true,
			Header{},
			"fails to trigger error on an input byte of one",
		},
		{
			[]byte{0x25},
			true,
			Header{},
			"fails to trigger error on an input byte of one",
		},
		{
			[]byte{0x20, 0x01},
			false,
			Header{2, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"fails to work with an input of two bytes for version 1, request packet type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0xF0, 0x01},
			false,
			Header{15, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"fails to work with an input of two bytes for version 15 (max version), request packet type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x10, 0x02},
			false,
			Header{1, true, 0x02},
			"fails to work with an input of two bytes for version 1, request packet type with encryption type 0x02",
		},
		{
			[]byte{0x10, 0x3F},
			false,
			Header{1, true, 0x3F},
			"fails to work with an input of two bytes for version 1, request packet type with encryption type 0x3F (max encryption number)",
		},
		{
			[]byte{0x10, 0x00},
			false,
			Header{1, true, 0x00},
			"fails to work with an input of two bytes for version 1, request packet type with encryption type 0x00",
		},
	}

	for i, test := range tests {
		result, err := binaryDecode(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("Expected error but did not return error on test case: %d, reason: %s", i, test.onErrorStr)
		}

		if result != test.expectedResult {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}

}
