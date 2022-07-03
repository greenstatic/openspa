package openspalib_old

import (
	"errors"
	"testing"
)

func TestByteInSlice(t *testing.T) {
	tests := []struct {
		inputDataElm   byte
		inputDataSlice []byte
		expectedResult bool
		onErrorStr     string
	}{
		// Test case: 1
		{
			0x1,
			[]byte{0x1, 0x10, 0x8, 0x17},
			true,
			"failed to detect element in the slice",
		},
		// Test case: 2
		{
			0x0,
			[]byte{0x1, 0x10, 0x8, 0x17},
			false,
			"failed to detect that element is not in the slice",
		},
		// Test case: 3
		{
			0x0,
			[]byte{},
			false,
			"failed to detect that the element is not in an empty slice",
		},
		// Test case: 4
		{
			0x0,
			[]byte{0x0},
			true,
			"failed to detect that the searched element is the only element in the slice",
		},
		// Test case: 5
		{
			0x8,
			[]byte{0x8, 0x8, 0x0},
			true,
			"failed to detect that the searched element is the only element in the slice",
		},
	}

	for i, test := range tests {
		result := byteInSlice(test.inputDataElm, test.inputDataSlice)

		if result != test.expectedResult {
			t.Errorf("Test case: %d failed, %v != %v, reason: %s",
				i+1, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		inputData      string
		expectedErr    error
		expectedResult bool
		onErrorStr     string
	}{
		{
			"193.2.1.66",
			nil,
			false,
			"IPv4 address 193.2.1.66",
		},
		{
			"212.235.188.20",
			nil,
			false,
			"IPv4 address 212.235.188.20",
		},
		{
			"2001:1470:8000::66",
			nil,
			true,
			"IPv6 address 2001:1470:8000::66",
		},
		{
			"2a02:7a8:1:250::80:1",
			nil,
			true,
			"IPv6 address 2a02:7a8:1:250::80:1",
		},
		{
			"",
			ErrBadIP,
			false,
			"empty string",
		},
		{
			"778.22.21.1",
			ErrBadIP,
			false,
			"wrongly formatted IPv4 address 778.22.21.1",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := isIPv6(test.inputData)

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed (%s), returned boolean does not match %v != %v",
				testNo, test.onErrorStr, test.expectedResult, result)
		}
	}
}
