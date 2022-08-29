package tools

import "testing"

func TestIsIPv6(t *testing.T) {

	tests := []struct {
		inputData      string
		expectedErr    bool
		expectedResult bool
		onErrorStr     string
	}{
		{
			"193.2.1.66",
			false,
			false,
			"failed to detect IPv4 address 193.2.1.66",
		},
		{
			"212.235.188.20",
			false,
			false,
			"failed to detect IPv4 address 212.235.188.20",
		},
		{
			"2001:1470:8000::66",
			false,
			true,
			"failed to detect IPv6 address 2001:1470:8000::66",
		},
		{
			"2a02:7a8:1:250::80:1",
			false,
			true,
			"failed to detect IPv6 address 2a02:7a8:1:250::80:1",
		},
	}

	for i, test := range tests {
		result, err := IsIPv6(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		if result != test.expectedResult {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestElementInSlice(t *testing.T) {

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
		result := ElementInSlice(test.inputDataElm, test.inputDataSlice)

		if result != test.expectedResult {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestCompareTwoByteSlices(t *testing.T) {
	tests := []struct {
		inputSlice1    []byte
		inputSlice2    []byte
		expectedResult bool
		onErrorStr     string
	}{
		{
			[]byte{},
			[]byte{},
			true,
			"fails to work when both slices are empty",
		},
		{
			[]byte{0x1},
			[]byte{},
			false,
			"fails to work when first slice is not empty and the second is",
		},
		{
			[]byte{},
			[]byte{0x1},
			false,
			"fails to work when second slice is not empty and the first is",
		},
		{
			[]byte{0x1},
			[]byte{0x1},
			true,
			"fails to work when both slices contain one (the same) byte",
		},
		{
			[]byte{0x1},
			[]byte{0x1, 0x1},
			false,
			"fails to work when both slices contain the same element but the second slice is longer",
		},
		{
			[]byte{0x9, 0x4},
			[]byte{0x1, 0x1},
			false,
			"fails to work when both slices are the same length but contain completely different elements",
		},
		{
			[]byte{0x9, 0x4},
			[]byte{0x1, 0x1, 0x5},
			false,
			"fails to work when both slices are the different lengths and contain completely different elements",
		},
	}

	for _, test := range tests {
		result := CompareTwoByteSlices(test.inputSlice1, test.inputSlice2)

		if result != test.expectedResult {
			t.Errorf("%v != %v, reason: %s", result, test.expectedResult, test.onErrorStr)
		}
	}
}
