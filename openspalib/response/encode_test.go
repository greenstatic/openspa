package response

import (
	"github.com/greenstatic/openspalib/tools"
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	tests := []struct {
		inputData      time.Time
		expectedResult []byte
		onErrorStr     string
	}{
		{
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
			"failed to encode a valid timestamp for the year 2018",
		},
		{
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
			"failed to encode a valid timestamp for the year 2030",
		},
		{
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
			"failed to encode a valid timestamp for the year 2060",
		},
		{
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
			"failed to encode a valid timestamp for the year 3018",
		},
	}

	for i, test := range tests {
		result := encodeTimestamp(test.inputData)

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestEncodePort(t *testing.T) {
	tests := []struct {
		inputData      uint16
		expectedResult []byte
		onErrorStr     string
	}{
		{
			1,
			[]byte{0x00, 0x01},
			"failed to encode port 1",
		},
		{
			0,
			[]byte{0x00, 0x00},
			"failed to encode port 0",
		},
		{
			10,
			[]byte{0x00, 0x0A},
			"failed to encode port 10",
		},
		{
			65534,
			[]byte{0xFF, 0xFE},
			"failed to encode port 65534",
		},
		{
			65535,
			[]byte{0xFF, 0xFF},
			"failed to encode port 65535",
		},
	}

	for i, test := range tests {
		result := encodePort(test.inputData)

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestEncodeDuration(t *testing.T) {
	tests := []struct {
		inputData      uint16
		expectedResult []byte
		onErrorStr     string
	}{
		{
			1,
			[]byte{0x00, 0x01},
			"failed to encode duration 1",
		},
		{
			0,
			[]byte{0x00, 0x00},
			"failed to encode duration 0",
		},
		{
			10,
			[]byte{0x00, 0x0A},
			"failed to encode duration 10",
		},
		{
			65534,
			[]byte{0xFF, 0xFE},
			"failed to encode duration 65534",
		},
		{
			65535,
			[]byte{0xFF, 0xFF},
			"failed to encode duration 65535",
		},
	}

	for i, test := range tests {
		result := encodeDuration(test.inputData)

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}
