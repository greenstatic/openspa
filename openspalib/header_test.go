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
			[]byte{0x20, 0x00, 0x01, 0x00},
			nil,
			Header{2, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"header from four byte slice - version 2, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 2
		{
			[]byte{0x28, 0x00, 0x01, 0x00},
			nil,
			Header{2, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"header from four byte slice - version 2, response type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			[]byte{0x20, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
			nil,
			Header{2, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0xFF},
			"header from byte slice greater than four - version 2, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
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
			[]byte{0x25, 0x12},
			ErrHeaderInvalid,
			Header{},
			"too short byte slice",
		},
		// Test case: 6
		{
			[]byte{0x10, 0x00, 0x01, 0x00},
			ErrProtocolVersionNotSupported{1},
			Header{},
			"unsupported version (1)",
		},
		// Test case: 7
		{
			[]byte{0x20, 0x00, 0x02, 0x00},
			ErrCipherSuiteNotSupported{0x02},
			Header{},
			"failed to return error for unsupported cipher method (0x2)",
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
			Header{1, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			ErrProtocolVersionNotSupported{1},
			[]byte{},
			"encode header version 1, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		//Test case: 2
		{
			Header{Version, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			nil,
			[]byte{0x20, 0x00, 0x01, 0x00},
			"header version 2, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			Header{Version, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 12},
			nil,
			[]byte{0x28, 0x00, 0x01, 0x0C},
			"encode header version 2, response type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
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
			Header{15, true, 63, 0},
			ErrProtocolVersionNotSupported{15},
			[]byte{},
			"encode header version 15, request type with encryption method 63",
		},
		// Test case: 6
		{
			Header{Version, true, 0x02, 0},
			ErrCipherSuiteNotSupported{0x02},
			[]byte{},
			"encode header version 15, request type with encryption method 0x02",
		},
		// Test case: 7
		{
			Header{16, true, 64, 0},
			ErrProtocolVersionNotSupported{16},
			[]byte{},
			"encode overflow with header version 16 and encryption method 64 (both one value too large from the max value)",
		},
		// Test case: 8
		{
			Header{Version, true, 0x64, 0},
			ErrCipherSuiteNotSupported{0x64},
			[]byte{},
			"encode header version 2 and encryption method 0x64",
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
			Header{1, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 16},
			nil,
			[]byte{0x10, 0x00, 0x01, 0x10},
			"encode header version 1, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256 with offset 16",
		},
		//Test case: 2
		{
			Header{2, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			nil,
			[]byte{0x20, 0x00, 0x01, 0x00},
			"header version 2, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			Header{2, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 13},
			nil,
			[]byte{0x28, 0x00, 0x01, 0x0d},
			"encode header version 2, response type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256 with offset 13",
		},
		// Test case: 4
		{
			Header{},
			nil,
			[]byte{0x08, 0x00, 0x00, 0x00},
			"encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 0x63, 0},
			nil,
			[]byte{0xF0, 0x00, 0x63, 0x00},
			"encode header version 15, request type with cipher suite 0x63",
		},
		// Test case: 6
		{
			Header{16, true, 0x64, 0},
			nil,
			[]byte{0x00, 0x00, 0x64, 0x00},
			"version field overflow with value 16",
		},
		// Test case: 6
		{
			Header{2, true, 0x400, 0},
			nil,
			[]byte{0x20, 0x00, 0x0, 0x00},
			"cipher suite overflow with value 0x400",
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
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match: %v != %v",
				testNo, test.onErrorStr, test.expectedResult, result)
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
			Header{1, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			nil,
			[]byte{0x10, 0x00, 0x01, 0x00},
			"encode header version 1, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		//Test case: 2
		{
			Header{2, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			nil,
			[]byte{0x20, 0x00, 0x01, 0x00},
			"header version 2, request type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			Header{2, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			nil,
			[]byte{0x28, 0x00, 0x01, 0x00},
			"encode header version 2, response type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 4
		{
			Header{},
			nil,
			[]byte{0x08, 0x00, 0x00, 0x00},
			"encode empty header",
		},
		// Test case: 5
		{
			Header{15, true, 0x63, 0},
			nil,
			[]byte{0xF0, 0x00, 0x63, 0x00},
			"encode header version 15, request type with cipher suite 0x63",
		},
		// Test case: 6
		{
			Header{16, true, 0x64, 0},
			nil,
			[]byte{0x00, 0x00, 0x64, 0x00},
			"version field overflow with value 16",
		},
		// Test case: 6
		{
			Header{2, true, 0x400, 0},
			nil,
			[]byte{0x20, 0x00, 0x00, 0x00},
			"cipher suite overflow with value 0x400",
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
		Version:     Version,
		IsRequest:   false,
		CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
	}
	var buff []byte
	for i := 0; i < b.N; i++ {
		buff, _ = headerMarshal(h)
	}
	_ = buff // try to avoid the compiler from optimizing the non-used returned slice
}

func Benchmark__HeaderMarshal2(b *testing.B) {
	h := Header{
		Version:     Version,
		IsRequest:   false,
		CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
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
			[]byte{0x10, 0x0, 0x01, 0x00},
			nil,
			Header{1, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"input of four bytes for version 1, request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 2
		{
			[]byte{0x18, 0x00, 0x01, 0x00},
			nil,
			Header{1, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"input of four bytes for version 1, response packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			[]byte{0x28, 0x00, 0x01, 0x00},
			nil,
			Header{Version, false, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"input of four bytes for version 2, response packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 4
		{
			[]byte{0x20, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			nil,
			Header{2, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0xFF},
			"larger than four byte input for version 1, request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
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
			[]byte{0x20, 0x00, 0x01, 0x00},
			nil,
			Header{Version, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"input of four bytes for version 2, request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 7
		{
			[]byte{0xF0, 0x00, 0x01, 0x00},
			nil,
			Header{15, true, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, 0},
			"input of four bytes for version 15 (max version), request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 8
		{
			[]byte{0x10, 0x00, 0x02, 0x00},
			nil,
			Header{1, true, 0x02, 0},
			"input of four bytes for version 1, request packet type with encryption type 0x02",
		},
		// Test case: 9
		{
			[]byte{0x10, 0x00, 0x3F, 0x00},
			nil,
			Header{1, true, 0x3F, 0},
			"input of four bytes for version 1, request packet type with cipher suite 0x3F",
		},
		// Test case: 10
		{
			[]byte{0x10, 0x00, 0x00, 0x00},
			nil,
			Header{1, true, 0x00, 0},
			"input of four bytes for version 1, request packet type with cipher suite 0x00",
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
