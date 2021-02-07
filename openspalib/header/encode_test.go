package header

import (
	"testing"
)

// Tests the func binaryEncode
func TestBinaryEncode(t *testing.T) {

	tests := []struct {
		inputData      Header
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		{
			Header{1, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			false,
			[]byte{0x10, 0x01},
			"fails to encode header version 1, request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{2, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			false,
			[]byte{0x20, 0x01},
			"fails to encode header version 1, request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{2, false, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			false,
			[]byte{0x28, 0x01},
			"fails to encode header version 2, response type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{},
			false,
			[]byte{0x08, 0x00},
			"fails to encode empty header",
		},
		{
			Header{15, true, 63},
			false,
			[]byte{0xF0, 0x3F},
			"fails to encode header version 15, request type with encryption method 63",
		},
		{
			Header{16, true, 64},
			false,
			[]byte{0x00, 0x00},
			"fails to encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
	}

	for i, test := range tests {
		result := test.inputData.binaryEncode()

		if len(result) != len(test.expectedResult) {
			t.Errorf("Expected different header encoded length on test case: %d, %v != %v, reason: %s",
				i, len(result), len(test.expectedResult), test.onErrorStr)
			continue
		}

		for j := range result {
			if result[j] != test.expectedResult[j] {
				t.Errorf("Expected different header bytes on test case: %d, %v != %v, reason: %s",
					i, result, test.expectedResult, test.onErrorStr)
			}
		}

	}
}
