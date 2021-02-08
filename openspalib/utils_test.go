package openspalib

import "testing"

func TestByteInSlice(t *testing.T) {
	tests := []struct {
		inputDataElm   byte
		inputDataSlice []byte
		expectedResult bool
		onErrorStr     string
	}{
		{
			0x1,
			[]byte{0x1, 0x10, 0x8, 0x17},
			true,
			"fails to detect element in the slice",
		},
		{
			0x0,
			[]byte{0x1, 0x10, 0x8, 0x17},
			false,
			"fails to detect that element is not in the slice",
		},
		{
			0x0,
			[]byte{},
			false,
			"fails to detect that the element is not in an empty slice",
		},
		{
			0x0,
			[]byte{0x0},
			true,
			"fails to detect that the searched element is the only element in the slice",
		},
		{
			0x8,
			[]byte{0x8, 0x8, 0x0},
			true,
			"fails to detect that the searched element is the only element in the slice",
		},
	}

	for i, test := range tests {
		result := byteInSlice(test.inputDataElm, test.inputDataSlice)

		if result != test.expectedResult {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}
