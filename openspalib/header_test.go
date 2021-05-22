package openspalib

import (
	"bytes"
	"errors"
	"testing"
)

func TestHeaderDecode(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult Header
		onErrorStr     string
	}{
		// Test case: 1
		{
			[]byte{0x20, 0x01},
			nil,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"header from two byte slice - version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 2
		{
			[]byte{0x28, 0x01},
			nil,
			Header{2, false, EncryptionMethodRSA2048WithAES256CBC},
			"header from two byte slice - version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			[]byte{0x20, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			nil,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"header from byte slice greater than two - version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			[]byte{0x20},
			ErrHeaderInvalid,
			Header{},
			"too short byte slice",
		},
		// Test case: 5
		{
			[]byte{0x25},
			ErrHeaderInvalid,
			Header{},
			"too short byte slice",
		},
		// Test case: 6
		{
			[]byte{0x10, 0x01},
			ErrProtocolVersionNotSupported{1},
			Header{},
			"unsupported version (1)",
		},
		// Test case: 7
		{
			[]byte{0x20, 0x02},
			ErrEncryptionMethodNotSupported{0x02},
			Header{},
			"failed to return error for unsupported encryption method (2)",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := HeaderDecode(test.inputData)

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed (%s), returned header does not match, header: %v != %v",
				testNo, test.onErrorStr, test.expectedResult, result)
		}
	}
}

func TestHeaderEncode(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    error
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			ErrProtocolVersionNotSupported{1},
			[]byte{},
			"encode header version 1, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		//Test case: 2
		{
			Header{Version, true, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x20, 0x01},
			"header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			Header{Version, false, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x28, 0x01},
			"encode header version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			Header{},
			ErrProtocolVersionNotSupported{0},
			[]byte{},
			"encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 63},
			ErrProtocolVersionNotSupported{15},
			[]byte{},
			"encode header version 15, request type with encryption method 63",
		},
		// Test case: 6
		{
			Header{Version, true, 0x02},
			ErrEncryptionMethodNotSupported{0x02},
			[]byte{},
			"encode header version 15, request type with encryption method 0x02",
		},
		// Test case: 7
		{
			Header{16, true, 64},
			ErrProtocolVersionNotSupported{16},
			[]byte{},
			"encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
		// Test case: 8
		{
			Header{Version, true, 64},
			ErrEncryptionMethodNotSupported{64},
			[]byte{},
			"encode header version 2 and encryption method 64 (overflow field)",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := test.inputData.Encode()

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match",
				testNo, test.onErrorStr)
		}
	}
}

func TestHeaderMarshal(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    error
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x10, 0x01},
			"encode header version 1, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		//Test case: 2
		{
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x20, 0x01},
			"header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			Header{2, false, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x28, 0x01},
			"encode header version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			Header{},
			nil,
			[]byte{0x08, 0x00},
			"encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 63},
			nil,
			[]byte{0xF0, 0x3F},
			"encode header version 15, request type with encryption method 63",
		},
		// Test case: 6
		{
			Header{16, true, 64},
			nil,
			[]byte{0x00, 0x00},
			"encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := headerMarshal(test.inputData)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match",
				testNo, test.onErrorStr)
		}

	}
}

func Test__HeaderMarshal2(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    error
		expectedResult []byte
		onErrorStr     string
	}{
		// Test case: 1
		{
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x10, 0x01},
			"encode header version 1, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		//Test case: 2
		{
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x20, 0x01},
			"header version 2, request type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			Header{2, false, EncryptionMethodRSA2048WithAES256CBC},
			nil,
			[]byte{0x28, 0x01},
			"encode header version 2, response type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			Header{},
			nil,
			[]byte{0x08, 0x00},
			"encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 63},
			nil,
			[]byte{0xF0, 0x3F},
			"encode header version 15, request type with encryption method 63",
		},
		// Test case: 6
		{
			Header{16, true, 64},
			nil,
			[]byte{0x00, 0x00},
			"encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		b := bytes.Buffer{}
		err := __headerMarshal2(test.inputData, &b)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, b.Bytes()) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match",
				testNo, test.onErrorStr)
		}

	}
}

func BenchmarkHeaderMarshal(b *testing.B) {
	h := Header{
		Version:          Version,
		IsRequest:        false,
		EncryptionMethod: EncryptionMethodRSA2048WithAES256CBC,
	}
	var buff []byte
	for i := 0; i < b.N; i++ {
		buff, _ = headerMarshal(h)
	}
	_ = buff // try to avoid the compiler from optimizing the non-used returned slice
}

func Benchmark__HeaderMarshal2(b *testing.B) {
	h := Header{
		Version:          Version,
		IsRequest:        false,
		EncryptionMethod: EncryptionMethodRSA2048WithAES256CBC,
	}
	// We store the buffer on purpose only once, to simulate the best possible result
	// if we would reuse the buffer when assembling the OpenSPA packet.
	buff := bytes.Buffer{}
	for i := 0; i < b.N; i++ {
		_ = __headerMarshal2(h, &buff)
	}
}

func TestHeaderUnmarshal(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult Header
		onErrorStr     string
	}{
		// Test case: 1
		{
			[]byte{0x10, 0x01},
			nil,
			Header{1, true, EncryptionMethodRSA2048WithAES256CBC},
			"input of two bytes for version 1, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 2
		{
			[]byte{0x18, 0x01},
			nil,
			Header{1, false, EncryptionMethodRSA2048WithAES256CBC},
			"input of two bytes for version 1, response packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 3
		{
			[]byte{0x28, 0x01},
			nil,
			Header{Version, false, EncryptionMethodRSA2048WithAES256CBC},
			"input of two bytes for version 2, response packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 4
		{
			[]byte{0x20, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			nil,
			Header{2, true, EncryptionMethodRSA2048WithAES256CBC},
			"larger than two byte input for version 1, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 5
		{
			[]byte{0x10},
			ErrHeaderInvalid,
			Header{},
			"input byte of one",
		},
		// Test case: 6
		{
			[]byte{0x20, 0x01},
			nil,
			Header{Version, true, EncryptionMethodRSA2048WithAES256CBC},
			"input of two bytes for version 2, request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 7
		{
			[]byte{0xF0, 0x01},
			nil,
			Header{15, true, EncryptionMethodRSA2048WithAES256CBC},
			"input of two bytes for version 15 (max version), request packet type with EncryptionMethodRSA2048WithAES256CBC",
		},
		// Test case: 8
		{
			[]byte{0x10, 0x02},
			nil,
			Header{1, true, 0x02},
			"input of two bytes for version 1, request packet type with encryption type 0x02",
		},
		// Test case: 9
		{
			[]byte{0x10, 0x3F},
			nil,
			Header{1, true, 0x3F},
			"input of two bytes for version 1, request packet type with encryption type 0x3F (max encryption number)",
		},
		// Test case: 10
		{
			[]byte{0x10, 0x00},
			nil,
			Header{1, true, 0x00},
			"input of two bytes for version 1, request packet type with encryption type 0x00",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := headerUnmarshal(test.inputData)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed (%s), returned header does not match, header: %v != %v",
				testNo, test.onErrorStr, test.expectedResult, result)
		}
	}
}

func TestErrProtocolVersionNotSupported(t *testing.T) {
	tests := []struct {
		inputData   uint8
		expectedErr string
	}{
		// Test case: 1
		{
			inputData:   1,
			expectedErr: "protocol version 1 not supported",
		},
		// Test case: 2
		{
			inputData:   25,
			expectedErr: "protocol version 25 not supported",
		},
		// Test case: 3
		{
			inputData:   0,
			expectedErr: "protocol version 0 not supported",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		err := ErrProtocolVersionNotSupported{test.inputData}
		if test.expectedErr != err.Error() {
			t.Errorf("Test case: %d failed, errors did not match: %s != %s",
				testNo, test.expectedErr, err.Error())
		}
	}
}

func TestErrEncryptionMethodNotSupported(t *testing.T) {
	tests := []struct {
		inputData   EncryptionMethod
		expectedErr string
	}{
		// Test case: 1
		{
			inputData:   EncryptionMethod(0),
			expectedErr: "encryption method 0 not supported",
		},
		// Test case: 2
		{
			inputData:   EncryptionMethod(1),
			expectedErr: "encryption method 1 not supported",
		},
		// Test case: 3
		{
			inputData:   EncryptionMethod(123),
			expectedErr: "encryption method 123 not supported",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		err := ErrEncryptionMethodNotSupported{test.inputData}
		if test.expectedErr != err.Error() {
			t.Errorf("Test case: %d failed, errors did not match: %s != %s",
				testNo, test.expectedErr, err.Error())
		}
	}
}
