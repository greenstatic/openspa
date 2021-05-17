package openspalib

import (
	"testing"
)

func TestHeaderDecode(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    bool
		expectedResult Header
		onErrorStr     string
	}{
		{
			[]byte{0x20, 0x01},
			false,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to decode header from two byte slice - version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		{
			[]byte{0x28, 0x01},
			false,
			Header{2, false, EncryptionMethodRSA2048WithAES256CBC},
			"failed to decode header from two byte slice - version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		{
			[]byte{0x20, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			false,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to decode header from byte slice greater than two - version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		{
			[]byte{0x20},
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
			[]byte{0x10, 0x01},
			true,
			Header{},
			"failed to return error for unsupported version (1)",
		},
		{
			[]byte{0x20, 0x02},
			true,
			Header{},
			"failed to return error for unsupported crypto suite (2)",
		},
	}

	for i, test := range tests {
		result, err := HeaderDecode(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("Test case: %d failed, reason: %s",
				i+1, test.onErrorStr)
		}

		if result != test.expectedResult {
			t.Errorf("Test case: %d failed, %v != %v, reason: %s",
				i+1, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestHeaderEncode(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			false,
			[]byte{0x20, 0x01},
			"failed to encode header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 2
		{
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			true,
			[]byte{},
			"failed to return error on encoding header version 1 (unsupported version), request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			Header{1, false, EncryptionMethodRSA2048WithAES256CBC},
			true,
			[]byte{},
			"failed to return error on encoding unsupported header version 1, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			Header{2, true, 0x02},
			true,
			[]byte{},
			"failed to return error on encoding header version 2, request type with unsupported encryption method 0x02",
		},
		// Test case: 5
		{
			Header{16, true, EncryptionMethodRSA2048WithAES256CBC},
			true,
			[]byte{},
			"failed to return error on encoding unsupported header version 16 (value can't be ever supported), request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 6
		{
			Header{15, true, 0x02},
			true,
			[]byte{},
			"failed to return error on encoding header version 15, request type with unsupported encryption method 0x02",
		},
		// Test case: 7
		{
			Header{2, true, 0x3F},
			true,
			[]byte{},
			"failed to return error on encoding header version 2, request type with unsupported encryption method 63 (0x3F)",
		},
		// Test case: 8
		{
			Header{2, true, 0x40},
			true,
			[]byte{},
			"failed to encode header version 2, request type with unsupported encryption method 64 (0x40) (value can't be ever supported)",
		},
	}

	for i, test := range tests {
		result, err := test.inputData.Encode()
		if err != nil != test.expectedErr {
			t.Errorf("Test case: %d failed, reason: %s", i+1, test.onErrorStr)
		}

		if len(result) != len(test.expectedResult) {
			t.Errorf("Test case: %d failed, %v != %v, reason: %s",
				i+1, len(result), len(test.expectedResult), test.onErrorStr)
			continue
		}

		for j := range result {
			if result[j] != test.expectedResult[j] {
				t.Errorf("Test case: %d failed, %v != %v, reason: %s",
					i+1, result, test.expectedResult, test.onErrorStr)
			}
		}
	}
}

func TestHeaderMarshal(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			false,
			[]byte{0x20, 0x01},
			"failed to encode header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 2
		{
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			false,
			[]byte{0x20, 0x01},
			"failed to encode header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			Header{2, false, EncryptionMethodRSA2048WithAES256CBC},
			false,
			[]byte{0x28, 0x01},
			"failed to encode header version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			Header{},
			false,
			[]byte{0x08, 0x00},
			"failed to encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 63},
			false,
			[]byte{0xF0, 0x3F},
			"failed to encode header version 15, request type with encryption method 63",
		},
		// Test case: 6
		{
			Header{16, true, 64},
			false,
			[]byte{0x00, 0x00},
			"failed to encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
	}

	for i, test := range tests {
		result, err := headerMarshal(test.inputData)
		if err != nil {
			t.Error(err)
		}

		if len(result) != len(test.expectedResult) {
			t.Errorf("Test case: %d failed, %v != %v, reason: %s",
				i+1, len(result), len(test.expectedResult), test.onErrorStr)
			continue
		}

		for j := range result {
			if result[j] != test.expectedResult[j] {
				t.Errorf("Test case: %d failed, %v != %v, reason: %s",
					i+1, result, test.expectedResult, test.onErrorStr)
			}
		}

	}
}

func TestHeaderUnmarshal(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    bool
		expectedResult Header
		onErrorStr     string
	}{
		// Test case: 1
		{
			[]byte{0x10, 0x01},
			false,
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to work with an input of two bytes for version 1, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 2
		{
			[]byte{0x18, 0x01},
			false,
			Header{1, false, EncryptionMethodRSA2048WithAES256CBC},
			"failed to work with an input of two bytes for version 1, response packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			[]byte{0x10, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			false,
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to work with a larger than two byte input for version 1, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			[]byte{0x10},
			true,
			Header{},
			"failed to trigger error on an input byte of one",
		},
		// Test case: 5
		{
			[]byte{0x25},
			true,
			Header{},
			"failed to trigger error on an input byte of one",
		},
		// Test case: 6
		{
			[]byte{0x20, 0x01},
			false,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to work with an input of two bytes for version 1, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 7
		{
			[]byte{0xF0, 0x01},
			false,
			Header{15, true, EncryptionMethodRSA2048WithAES256CBC},
			"failed to work with an input of two bytes for version 15 (max version), request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 8
		{
			[]byte{0x10, 0x02},
			false,
			Header{1, true, 0x02},
			"failed to work with an input of two bytes for version 1, request packet type with encryption type 0x02",
		},
		// Test case: 9
		{
			[]byte{0x10, 0x3F},
			false,
			Header{1, true, 0x3F},
			"failed to work with an input of two bytes for version 1, request packet type with encryption type 0x3F (max encryption number)",
		},
		// Test case: 10
		{
			[]byte{0x10, 0x00},
			false,
			Header{1, true, 0x00},
			"failed to work with an input of two bytes for version 1, request packet type with encryption type 0x00",
		},
	}

	for i, test := range tests {
		result, err := headerUnmarshal(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("Test case: %d failed, reason: %s",
				i+1, test.onErrorStr)
		}

		if result != test.expectedResult {
			t.Errorf("Test case: %d failed, %v != %v, reason: %s",
				i+1, result, test.expectedResult, test.onErrorStr)
		}
	}
}
