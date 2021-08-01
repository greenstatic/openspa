package openspalib

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestClientDeviceIdEncode(t *testing.T) {
	tests := []struct {
		inputDataClientDeviceID string
		expectedErr             error
		expectedResult          []byte
		onErrorStr              string
	}{
		// Test case: 1
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"valid UUID v4 string",
		},
		// Test case: 2
		{
			"8f97e69c1bb14d2f8cb024f2e874254d",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"valid UUID without dashes",
		},
		// Test case: 3
		{
			"8f97e69c1bb14d2f8cb024f2e874254",
			ErrDeviceIdInvalid,
			[]byte{},
			"too short UUID without dashes",
		},
		// Test case: 4
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254",
			ErrDeviceIdInvalid,
			[]byte{},
			"too short UUID with dashes",
		},
		// Test case: 5
		{
			"8F97E69C-1BB1-4D2F-8CB0-24F2E874254D",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
			"valid UUID with capital letters",
		},
		// Test case: 6
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de",
			ErrDeviceIdInvalid,
			[]byte{},
			"too long UUID with dashes, added a single letter to the uuid (impartial byte)",
		},
		// Test case: 7
		{
			"8f97e69c1bb14d2f8cb024f2e874254dE",
			ErrDeviceIdInvalid,
			[]byte{},
			"too long UUID without dashes, added a single letter to the uuid (impartial byte)",
		},
		// Test case: 8
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de1",
			ErrDeviceIdInvalid,
			[]byte{},
			"too long UUID with dashes",
		},
		// Test case: 9
		{
			"8f97e69c1bb14d2f8cb024f2e874254de1",
			ErrDeviceIdInvalid,
			[]byte{},
			"too long UUID without dashes",
		},
		// Test case: 10
		{
			"1",
			ErrDeviceIdInvalid,
			[]byte{},
			"string with a single character",
		},
		// Test case: 11
		{
			"",
			ErrDeviceIdInvalid,
			[]byte{},
			"empty string",
		},
		// Test case: 12
		{
			"8f97e69z1bb14d2f8cb024f2e874254d",
			hex.InvalidByteError('z'),
			[]byte{},
			"string that contains a non hex character",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := clientDeviceIdEncode(test.inputDataClientDeviceID)

		if !errors.Is(test.expectedErr, err) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match",
				testNo, test.onErrorStr)
		}
	}
}

func TestTimestampEncode(t *testing.T) {
	tests := []struct {
		inputData      time.Time
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
			"encode valid timestamp for the year 2018",
		},
		// Test case: 2
		{
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
			"encode valid timestamp for the year 2030",
		},
		// Test case: 3
		{
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
			"encode valid timestamp for the year 2060",
		},
		// Test case: 4
		{
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
			"encode valid timestamp for the year 3018",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result := timestampEncode(test.inputData)

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match",
				testNo, test.onErrorStr)
		}
	}
}

func TestTimestampDecode(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult time.Time
		onErrorStr     string
	}{
		// Test case: 1
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
			nil,
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
			"encode valid timestamp for the year 2018",
		},
		// Test case: 2
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
			nil,
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
			"encode valid timestamp for the year 2030",
		},
		// Test case: 3
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
			nil,
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
			"encode valid timestamp for the year 2060",
		},
		// Test case: 4
		{
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
			nil,
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
			"encode valid timestamp for the year 3018",
		},
		// Test case: 5
		{
			[]byte{},
			ErrTimestampInvalid,
			time.Time{},
			"empty input",
		},
		// Test case: 6
		{
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			nil,
			time.Unix(0, 0),
			"birth of time",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := timestampDecode(test.inputData)

		if !errors.Is(test.expectedErr, err) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
			t.Errorf("Test case: %d failed (%s), returned time does not match, time:%v != time:%v",
				testNo, test.onErrorStr, test.expectedResult, result)
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

		if !bytes.Equal(result, test.expectedResult) {
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

		if !bytes.Equal(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestErrCipherSuiteNotSupported(t *testing.T) {
	tests := []struct {
		inputData   CipherSuiteId
		expectedErr string
	}{
		// Test case: 1
		{
			inputData:   CipherSuiteId(0),
			expectedErr: "cipher suite 0 not supported",
		},
		// Test case: 2
		{
			inputData:   CipherSuiteId(1),
			expectedErr: "cipher suite 1 not supported",
		},
		// Test case: 3
		{
			inputData:   CipherSuiteId(123),
			expectedErr: "cipher suite 123 not supported",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		err := ErrCipherSuiteNotSupported{test.inputData}
		if test.expectedErr != err.Error() {
			t.Errorf("Test case: %d failed, error message did not match: %s != %s",
				testNo, test.expectedErr, err.Error())
		}
	}
}

func TestEncodeMiscField(t *testing.T) {
	tests := []struct {
		behindNAT bool
		signatureOffset uint
		expectedResult []byte
		expectedErr error
	} {
		// Test case: 1
		{
			behindNAT: true,
			signatureOffset: 13,
			expectedResult: []byte{0x80, 0x00, 0x00, 0x0D},
			expectedErr:     nil,
		},
		// Test case: 2
		{
			behindNAT: false,
			signatureOffset: 10,
			expectedResult: []byte{0x00, 0x00, 0x00, 0x0A},
			expectedErr:     nil,
		},
		// Test case: 3
		{
			behindNAT: true,
			signatureOffset: 1023,
			expectedResult: []byte{0x80, 0x00, 0x03, 0xFF},
			expectedErr:     nil,
		},
		// Test case: 4
		{
			behindNAT: false,
			signatureOffset: 1035,
			expectedResult: nil,
			expectedErr: ErrSignatureOffsetTooLarge,
		},
		// Test case: 5
		{
			behindNAT: false,
			signatureOffset: 1024,
			expectedResult: nil,
			expectedErr: ErrSignatureOffsetTooLarge,
		},
	}

	for i, test := range tests {
		testNo := i + 1

		result, err := encodeMiscField(test.behindNAT, test.signatureOffset)
		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, expected err: %v, returned err: %v", testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed, %x != %x", testNo, test.expectedResult, result)
		}
	}
}

