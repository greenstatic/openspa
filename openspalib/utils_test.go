package openspalib

import "testing"

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
