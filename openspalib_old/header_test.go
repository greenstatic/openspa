package openspalib_old

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
	}{
		// Test case: 1
		{
			[]byte{0x20, 0x3C, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0x3C,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
		},
		// Test case: 2
		{
			[]byte{0xA0, 0xFA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDUResponseType, Version),
				TransactionId: 0xFA,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
		},
		// Test case: 3
		{
			[]byte{0x20, 0xF0, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 0x1C, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0xF0,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
		},
		// Test case: 4
		{
			[]byte{0x20},
			ErrHeaderTooShort,
			Header{},
		},
		// Test case: 5
		{
			[]byte{0x25, 0x12, 0x00, 0x12, 0x12, 0x22, 0xAE},
			ErrHeaderTooShort,
			Header{},
		},
		// Test case: 6
		{
			[]byte{0x10, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrProtocolVersionNotSupported{1},
			Header{},
		},
		// Test case: 7
		{
			[]byte{0x00, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrProtocolVersionNotSupported{0},
			Header{},
		},
		// Test case: 8
		{
			[]byte{0x20, 0xF0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrCipherSuiteNotSupported{0x02},
			Header{},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := HeaderDecode(test.inputData)

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, error:%v != error:%v", testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, test.expectedResult, result)
		}
	}
}

func TestHeaderEncode(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    error
		expectedResult []byte
	}{
		// Test case: 1
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, 1),
				TransactionId: 0x47,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			ErrProtocolVersionNotSupported{1},
			[]byte{},
		},
		//Test case: 2
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0xE,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			nil,
			[]byte{0x20, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		// Test case: 3
		{
			Header{
				controlField:  controlFieldEncode(PDUResponseType, Version),
				TransactionId: 0xE,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			nil,
			[]byte{0xA0, 0x0E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		// Test case: 4
		{
			Header{},
			ErrProtocolVersionNotSupported{0},
			[]byte{},
		},
		// Test case: 5
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, 7),
				TransactionId: 1,
				CipherSuiteId: 63,
			},
			ErrProtocolVersionNotSupported{7},
			[]byte{},
		},
		// Test case: 6
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 1,
				CipherSuiteId: 0x2,
			},
			ErrCipherSuiteNotSupported{0x02},
			[]byte{},
		},
		// Test case: 7
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, 7),
				TransactionId: 1,
				CipherSuiteId: 0x2,
			},
			ErrProtocolVersionNotSupported{7},
			[]byte{},
		},
		// Test case: 8
		{
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 1,
				CipherSuiteId: 0x64,
			},
			ErrCipherSuiteNotSupported{0x64},
			[]byte{},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := test.inputData.Encode()

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, error: %v != %v", testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, test.expectedResult, result)
		}
	}
}

func TestHeaderMarshal(t *testing.T) {
	tests := []struct {
		inputData      Header
		expectedErr    error
		expectedResult []byte
	}{
		// Test case: 1
		{
			inputData: Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0x31,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			expectedErr:    nil,
			expectedResult: []byte{0x20, 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		//Test case: 2
		{
			inputData: Header{
				controlField:  controlFieldEncode(PDUResponseType, Version),
				TransactionId: 0xFF,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			expectedErr:    nil,
			expectedResult: []byte{0xA0, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		// Test case: 3
		{
			inputData: Header{
				controlField:  controlFieldEncode(PDURequestType, 4),
				TransactionId: 1,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
			expectedErr:    nil,
			expectedResult: []byte{0x40, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		// Test case: 4
		{
			inputData:      Header{},
			expectedErr:    nil,
			expectedResult: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := headerMarshal(test.inputData)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, error:%v != error:%v", testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, test.expectedResult, result)
		}

	}
}

func TestHeaderUnmarshal(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult Header
	}{
		// Test case: 1
		{
			[]byte{0x20, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0x04,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
		},
		// Test case: 2
		{
			[]byte{0xA0, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDUResponseType, 2),
				TransactionId: 0xFF,
				CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			},
		},
		// Test case: 3
		{
			[]byte{0xA0, 0x04, 0x01, 0x00},
			ErrHeaderTooShort,
			Header{},
		},
		// Test case: 4
		{
			[]byte{0x20, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			nil,
			Header{
				controlField:  controlFieldEncode(PDURequestType, 2),
				TransactionId: 0,
				CipherSuiteId: 0x1,
			},
		},
		// Test case: 5
		{
			[]byte{0x20},
			ErrHeaderTooShort,
			Header{},
		},
		// Test case: 6
		{
			[]byte{0x20, 0x04, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlField:  controlFieldEncode(PDURequestType, Version),
				TransactionId: 0x04,
				CipherSuiteId: 0x3F,
			},
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := headerUnmarshal(test.inputData)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, error:%v != error:%v", testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
			t.Errorf("Test case: %d failed, %v != %v", testNo, test.expectedResult, result)
		}
	}
}

func BenchmarkHeaderMarshal(b *testing.B) {
	h := Header{
		CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
	}
	h.SetVersion(Version)
	h.SetType(PDURequestType)

	var buff []byte
	for i := 0; i < b.N; i++ {
		buff, _ = headerMarshal(h)
	}
	_ = buff // try to avoid the compiler from optimizing the non-used returned slice
}

func Benchmark__HeaderMarshal2(b *testing.B) {
	h := Header{
		CipherSuiteId: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
	}
	h.SetVersion(Version)
	h.SetType(PDURequestType)

	// We store the buffer on purpose only once, to simulate the best possible result
	// if we would reuse the buffer when assembling the OpenSPA packet.
	buff := bytes.Buffer{}
	for i := 0; i < b.N; i++ {
		_ = __headerMarshal2(h, &buff)
	}
}

func TestErrProtocolVersionNotSupported(t *testing.T) {
	tests := []struct {
		inputData   int
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

func TestControlField(t *testing.T) {
	tests := []struct {
		inputPDUType   PDUType
		inputVersion   int
		expectedResult byte
	}{
		// Test case: 1
		{
			inputPDUType:   PDURequestType,
			inputVersion:   0,
			expectedResult: 0x00,
		},
		// Test case: 2
		{
			inputPDUType:   PDUResponseType,
			inputVersion:   1,
			expectedResult: 0x90,
		},
		// Test case: 3
		{
			inputPDUType:   PDUResponseType,
			inputVersion:   7,
			expectedResult: 0xF0,
		},
		// Test case: 4
		{
			inputPDUType:   PDUResponseType,
			inputVersion:   Version,
			expectedResult: 0xA0,
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result := controlFieldEncode(test.inputPDUType, test.inputVersion)

		if test.expectedResult != result {
			t.Fatalf("Test case: %d failed, returned byte does not match %x != %x",
				testNo, test.expectedResult, result)
		}

		resultType, resultVersion := controlFieldDecode(result)
		if test.inputPDUType != resultType {
			t.Fatalf("Test case: %d failed, type %x != %x", testNo, test.inputPDUType, resultType)
		}
		if test.inputVersion != resultVersion {
			t.Fatalf("Test case: %d failed, version %x != %x", testNo, test.inputVersion, resultVersion)
		}
	}
}
