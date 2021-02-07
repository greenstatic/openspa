package cryptography

import (
	"github.com/greenstatic/openspalib/tools"
	"testing"
)

func TestRandomKey(t *testing.T) {
	// See if multiple calls result in different values. There is a negligible probability that we will generate
	// two identical keys's.

	const testNo = 10000
	const keySize = 16

	results := make([][]byte, testNo)

	for i := 0; i < testNo; i++ {
		val, err := RandomKey(keySize)

		if err != nil {
			t.Errorf("Error returned while generating random key, iteration number: %d, error: %s", i, err)
		}

		results[i] = val
	}

	// See if any of the key's are the same
	for i := 0; i < len(results); i++ {
		for j := 0; j < len(results); j++ {
			if i == j {
				continue
			}

			if tools.CompareTwoByteSlices(results[i], results[j]) {
				t.Errorf("Generated duplicate key: %v", results[i])
			}
		}
	}

}

func TestPaddingPKCS7(t *testing.T) {

	tests := []struct {
		inputData      []byte
		inputDataSize  int
		expectedResult []byte
		onErrorStr     string
	}{
		{
			[]byte{0x05, 0xA2, 0x07},
			13, // 16 - 3 since the input data is three bytes long
			[]byte{0x05, 0xA2, 0x07, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
				0x0D, 0x0D, 0x0D},
			"failed to pad a three byte long slice",
		},
		{
			[]byte{0x05, 0xA2, 0x07, 0x49, 0xB3, 0xCC, 0xE1, 0x5E, 0x99, 0x10, 0xF1, 0x80, 0x00, 0x01,
				0x0F, 0x6E},
			16,
			[]byte{0x05, 0xA2, 0x07, 0x49, 0xB3, 0xCC, 0xE1, 0x5E, 0x99, 0x10, 0xF1, 0x80,
				0x00, 0x01, 0x0F, 0x6E, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10},
			"failed to pad a 16 byte slice with a size of 16",
		},
	}

	for i, test := range tests {
		result := PaddingPKCS7(test.inputData, test.inputDataSize)

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Bad padding for test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestPaddingPKCS7Remove(t *testing.T) {

	tests := []struct {
		inputData      []byte
		expectedError  bool
		expectedResult []byte
		onErrorStr     string
	}{
		{
			[]byte{0x05, 0xA2, 0x07, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
				0x0D, 0x0D, 0x0D},
			false,
			[]byte{0x05, 0xA2, 0x07},
			"failed to remove padding of size 3 bytes",
		},
		{
			[]byte{0x05, 0xA2, 0x07, 0x49, 0xB3, 0xCC, 0xE1, 0x5E, 0x99, 0x10, 0xF1, 0x80,
				0x00, 0x01, 0x0F, 0x6E, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
				0x10, 0x10, 0x10, 0x10, 0x10},
			false,
			[]byte{0x05, 0xA2, 0x07, 0x49, 0xB3, 0xCC, 0xE1, 0x5E, 0x99, 0x10, 0xF1, 0x80, 0x00, 0x01,
				0x0F, 0x6E},
			"failed to remove padding of size 16 bytes",
		},

		{
			[]byte{0x05, 0xA2, 0x07, 0x49, 0xB3, 0xCC, 0xE1, 0x5E, 0x99, 0x10, 0xF1, 0x80,
				0x00, 0x01, 0x0F, 0x6E, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
				0x41, 0x41, 0x41, 0x41, 0x41},
			true,
			[]byte{},
			"failed to return error when padding size exceeds the data slice",
		},
	}

	for i, test := range tests {
		result, err := PaddingPKCS7Remove(test.inputData)

		if err != nil != test.expectedError {
			t.Errorf("Unexpected error or lack of one for test case: %d, reason: %s", i, test.onErrorStr)
			t.Logf("%v", result)
			continue
		}

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Bad padding for test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}
