package header

import (
	"testing"
)

// Tests the func Decode
func TestDecode(t *testing.T) {

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
			"failed to decode header from two byte slice - version 1, request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x18, 0x01},
			false,
			Header{1, false, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"failed to decode header from two byte slice - version 1, response type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x10, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			false,
			Header{1, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			"failed to decode header from byte slice greater than two - version 1, request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			[]byte{0x10},
			true,
			Header{},
			"failed to return error on too short byte slice",
		},
		{
			[]byte{0x25},
			true,
			Header{},
			"failed to return error on too short byte slice",
		},
		{
			[]byte{0x20, 0x01},
			true,
			Header{},
			"failed to return error for unsupported version (2)",
		},
		{
			[]byte{0x10, 0x02},
			true,
			Header{},
			"failed to return error for unsupported encryption method (2)",
		},
	}

	for i, test := range tests {
		result, err := Decode(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("Expected error but did not return error on test case: %d, reason: %s", i, test.onErrorStr)
		}

		if result != test.expectedResult {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}

}

func TestEncode(t *testing.T) {

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
			true,
			[]byte{},
			"fails to return error on encoding header version 2 (unsupported version), request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{2, false, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			true,
			[]byte{},
			"fails to return error on encoding unsupported header version 2, response type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{1, true, 0x02},
			true,
			[]byte{},
			"fails to return error on encoding header version 1, request type with unsupported encryption method 0x02",
		},
		{
			Header{16, true, EncryptionMethod_RSA_2048_with_AES_256_CBC},
			true,
			[]byte{},
			"fails to return error on encoding unsupported header version 16 (value can't be ever supported), request type with EncryptionMethod_RSA_2048_with_AES_256_CBC",
		},
		{
			Header{15, true, 0x02},
			true,
			[]byte{},
			"fails to return error on encoding header version 1, request type with unsupported encryption method 0x02",
		},
		{
			Header{1, true, 0x3F},
			true,
			[]byte{},
			"fails to return error on encoding header version 1, request type with unsupported encryption method 63 (0x3F)",
		},
		{
			Header{1, true, 0x40},
			true,
			[]byte{},
			"fails to encode header version 1, request type with unsupported encryption method 64 (0x40) (value can't be ever supported)",
		},
	}

	for i, test := range tests {
		result, err := test.inputData.Encode()

		if err != nil != test.expectedErr {
			t.Errorf("Expected error but did not return error on test case: %d, reason: %s", i, test.onErrorStr)
		}

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
