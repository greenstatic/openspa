package openspalib

import (
	"testing"
	"time"
)

func TestEncodeClientDeviceID(t *testing.T) {
	tests := []struct {
		inputDataClientDeviceID string
		expectedErr             bool
		expectedResult          []byte
		onErrorStr              string
	}{
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
			false,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"failed to encode a valid UUID v4 string",
		},
		{
			"8f97e69c1bb14d2f8cb024f2e874254d",
			false,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"failed to accept a valid UUID without dashes",
		},
		{
			"8f97e69c1bb14d2f8cb024f2e874254",
			true,
			[]byte{},
			"failed to return error on a too short UUID without dashes",
		},
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254",
			true,
			[]byte{},
			"failed to return error on a too short UUID with dashes",
		},
		{
			"8F97E69C-1BB1-4D2F-8CB0-24F2E874254D",
			false,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"failed to accept a valid UUID with capital letters",
		},
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de",
			true,
			[]byte{},
			"failed to return error on a too long UUID with dashes, added a single letter to the uuid (impartial byte)",
		},
		{
			"8f97e69c1bb14d2f8cb024f2e874254dE",
			true,
			[]byte{},
			"failed to return error on a too long UUID without dashes, added a single letter to the uuid (impartial byte)",
		},
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de1",
			true,
			[]byte{},
			"failed to return error on a too long UUID with dashes",
		},
		{
			"8f97e69c1bb14d2f8cb024f2e874254de1",
			true,
			[]byte{},
			"failed to return error on a too long UUID without dashes",
		},
		{
			"1",
			true,
			[]byte{},
			"failed to return error with a string with a single character",
		},
		{
			"",
			true,
			[]byte{},
			"failed to return error with an empty string",
		},
		{
			"8f97e69z1bb14d2f8cb024f2e874254d",
			true,
			[]byte{},
			"failed to return error with a string that contains a non hex character",
		},
	}

	for i, test := range tests {
		result, err := encodeClientDeviceID(test.inputDataClientDeviceID)

		if err != nil != test.expectedErr {
			t.Errorf("test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		if !compareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestEncodeTimestamp(t *testing.T) {
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

		if !compareTwoByteSlices(result, test.expectedResult) {
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

		if !compareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestEncodeDuration(t *testing.T) {
	tests := []struct {
		inputData      time.Duration
		expectedResult []byte
		onErrorStr     string
	}{
		{
			time.Second * 1,
			[]byte{0x00, 0x01},
			"failed to encode duration 1",
		},
		{
			time.Second * 0,
			[]byte{0x00, 0x00},
			"failed to encode duration 0",
		},
		{
			time.Second * 10,
			[]byte{0x00, 0x0A},
			"failed to encode duration 10",
		},
		{
			time.Second * 65534,
			[]byte{0xFF, 0xFE},
			"failed to encode duration 65534",
		},
		{
			time.Second * 65535,
			[]byte{0xFF, 0xFF},
			"failed to encode duration 65535",
		},
	}

	for i, test := range tests {
		result := encodeDuration(test.inputData)

		if !compareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}
