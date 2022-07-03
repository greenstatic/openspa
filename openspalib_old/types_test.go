package openspalib_old

import (
	"bytes"
	"encoding/hex"
	"github.com/pkg/errors"
	"testing"
	"time"
)

func TestTimestampEncode(t *testing.T) {
	tests := []struct {
		inputData      time.Time
		expectedResult []byte
	}{
		// Test case: 1
		{
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
		},
		// Test case: 2
		{
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
		},
		// Test case: 3
		{
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
		},
		// Test case: 4
		{
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result := timestampEncode(test.inputData)

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, result, test.expectedResult)
		}
	}
}

func TestTimestampDecode(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult time.Time
	}{
		// Test case: 1
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
			nil,
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		// Test case: 2
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
			nil,
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		// Test case: 3
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
			nil,
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		// Test case: 4
		{
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
			nil,
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		// Test case: 5
		{
			[]byte{},
			ErrInvalidBytes,
			time.Time{},
		},
		// Test case: 6
		{
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			nil,
			time.Unix(0, 0),
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := timestampDecode(test.inputData)

		if !errors.Is(test.expectedErr, err) {
			t.Errorf("Test case: %d failed, error:%v != error:%v", testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
			t.Errorf("Test case: %d failed, time:%v != time:%v", testNo, test.expectedResult, result)
		}
	}
}

func TestClientDeviceUUIDEncode(t *testing.T) {
	tests := []struct {
		inputDataClientDeviceUUID string
		expectedErr               error
		expectedResult            []byte
	}{
		// Test case: 1
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
		},
		// Test case: 2
		{
			"8f97e69c1bb14d2f8cb024f2e874254d",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
		},
		// Test case: 3
		{
			"8f97e69c1bb14d2f8cb024f2e874254",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 4
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 5
		{
			"8F97E69C-1BB1-4D2F-8CB0-24F2E874254D",
			nil,
			[]byte{0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, 0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74,
				0x25, 0x4D},
		},
		// Test case: 6
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 7
		{
			"8f97e69c1bb14d2f8cb024f2e874254dE",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 8
		{
			"8f97e69c-1bb1-4d2f-8cb0-24f2e874254de1",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 9
		{
			"8f97e69c1bb14d2f8cb024f2e874254de1",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 10
		{
			"1",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 11
		{
			"",
			ErrInvalidInput,
			[]byte{},
		},
		// Test case: 12
		{
			"8f97e69z1bb14d2f8cb024f2e874254d",
			hex.InvalidByteError('z'),
			[]byte{},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := clientDeviceUUIDEncode(test.inputDataClientDeviceUUID)

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, error:%v != error:%v", testNo, test.expectedErr, err)
		}

		if !bytes.Equal(result, test.expectedResult) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, result, test.expectedResult)
		}
	}
}

func TestUint16Encode(t *testing.T) {
	tests := []struct {
		inputData      uint16
		expectedResult []byte
	}{
		{
			1,
			[]byte{0x00, 0x01},
		},
		{
			0,
			[]byte{0x00, 0x00},
		},
		{
			10,
			[]byte{0x00, 0x0A},
		},
		{
			65534,
			[]byte{0xFF, 0xFE},
		},
		{
			65535,
			[]byte{0xFF, 0xFF},
		},
	}

	for i, test := range tests {
		result := uint16Encode(test.inputData)

		if !bytes.Equal(result, test.expectedResult) {
			t.Errorf("Test case: %d failed, %v != %v", i, result, test.expectedResult)
		}
	}
}

func TestIPInfoEncode(t *testing.T) {
	tests := []struct {
		i              IPInfo
		expectedResult byte
	}{
		// Test case: 1
		{
			i: IPInfo{
				ClientBehindNAT: true,
			},
			expectedResult: 0x01,
		},
		// Test case: 2
		{
			i: IPInfo{
				ClientBehindNAT: false,
			},
			expectedResult: 0x00,
		},
	}

	for i, test := range tests {
		testNo := i + 1

		result := ipInfoEncode(test.i)

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed, %x != %x", testNo, test.expectedResult, result)
		}
	}
}

func TestIPInfoDecode(t *testing.T) {
	tests := []struct {
		input          byte
		expectedResult IPInfo
	}{
		// Test case: 1
		{
			input: 0x01,
			expectedResult: IPInfo{
				ClientBehindNAT: true,
			},
		},
		// Test case: 2
		{
			input: 0x00,
			expectedResult: IPInfo{
				ClientBehindNAT: false,
			},
		},
		// Test case: 3
		{
			input: 0x7A,
			expectedResult: IPInfo{
				ClientBehindNAT: false,
			},
		},
		// Test case: 4
		{
			input: 0x7B,
			expectedResult: IPInfo{
				ClientBehindNAT: true,
			},
		},
	}

	for i, test := range tests {
		testNo := i + 1

		result := ipInfoDecode(test.input)

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed, %v != %v", testNo, test.expectedResult, result)
		}
	}
}
