package openspalib

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
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
			[]byte{0x20, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{controlFieldEncode(PDURequestType, Version), 0x3C, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			"header pdu type: request, version: 2, cipher suite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, no additional header data",
		},
		// Test case: 2
		{
			[]byte{0xA0, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{controlFieldEncode(PDUResponseType, Version), 0x3C, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			"header pdu type: response, version: 2, cipher suite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, no additional header data",
		},
		// Test case: 3
		{
			[]byte{0x20, 0xF0, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 0x1C, 0x00, 0x00, 0x00},
			nil,
			Header{
				controlFieldEncode(PDURequestType, Version),
				0x3C,
				CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
				NewTLVContainer([]byte{0x12,0x34,0x00,0x01,0x1C,
					0x00,0x00,0x00,  // slack
				}, additionalHeaderDataLenMax)},
			"header pdu type: request, version: 2, cipher suite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, additional header data={type:0x1234, value:0x1C}",
		},
		// Test case: 4
		{
			[]byte{0x20},
			ErrHeaderTooShort,
			Header{},
			"too short byte slice",
		},
		// Test case: 5
		{
			[]byte{0x25, 0x12, 0x00, 0x12, 0x12, 0x22, 0xAE},
			ErrHeaderTooShort,
			Header{},
			"too short byte slice",
		},
		// Test case: 6
		{
			[]byte{0x10, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrProtocolVersionNotSupported{1},
			Header{},
			"unsupported version (1)",
		},
		// Test case: 7
		{
			[]byte{0x00, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrProtocolVersionNotSupported{0},
			Header{},
			"unsupported version (0)",
		},
		// Test case: 8
		{
			[]byte{0x20, 0xF0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00},
			ErrCipherSuiteNotSupported{0x02},
			Header{},
			"failed to return error for unsupported cipher method (0x2)",
		},
		// Test case: 9
		{
			[]byte{0x20, 0xF0, 0x01, 0x02, 0x12, 0x34, 0x00, 0x01, 0x1C, 0x00, 0x00},
			ErrHeaderInvalid,
			Header{},
			"header too short (one additional header data slack byte missing), pdu type: request, " +
				"version: 2, cipher suite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, " +
				"additional header data={type:0x1234, value:0x1C}",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := HeaderDecode(test.inputData)

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
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
			Header{controlFieldEncode(PDURequestType, 1), 0x47, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			ErrProtocolVersionNotSupported{1},
			[]byte{},
			"header type:request, version:1, tid:0x47 cipher suite:CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		//Test case: 2
		{
			Header{controlFieldEncode(PDURequestType, Version), 0xE, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			nil,
			[]byte{0x20, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			"header type:request, version:2, tid:0xE, cipher suite:CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			Header{controlFieldEncode(PDUResponseType, Version), 0xE, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			nil,
			[]byte{0xA0, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			"header type:response, version:2, tid:0xE, cipher suite:CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
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
			Header{controlFieldEncode(PDURequestType, 7), 1, 63, nil},
			ErrProtocolVersionNotSupported{7},
			[]byte{},
			"header type:request, version:7, tid:1, cipher suite:63",
		},
		// Test case: 6
		{
			Header{controlFieldEncode(PDURequestType, Version), 1, 0x2, nil},
			ErrCipherSuiteNotSupported{0x02},
			[]byte{},
			"not supported cipher suite",
		},
		// Test case: 7
		{
			Header{controlFieldEncode(PDURequestType, 7), 1, 0x2, nil},
			ErrProtocolVersionNotSupported{7},
			[]byte{},
			"overflow version field",
		},
		// Test case: 8
		{
			Header{controlFieldEncode(PDURequestType, Version), 1, 0x64, nil},
			ErrCipherSuiteNotSupported{0x64},
			[]byte{},
			"not supported cipher suite",
		},
		// Test case: 9
		{
			Header{controlFieldEncode(PDURequestType, Version), 1, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, NewTLVContainer(randomBytes(additionalHeaderDataLenMax+1), additionalHeaderDataLenMax+1)},
			ErrAdditionalHeaderDataTooLong,
			nil,
			"encode additional header data that is larger than PDU body offset",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := test.inputData.Encode()

		if !errors.Is(err, test.expectedErr) {
			t.Errorf("Test case: %d failed, returned error does not match, error: %v != %v",
				testNo, test.expectedErr, err)
		}

		if !bytes.Equal(test.expectedResult, result) {
			t.Errorf("Test case: %d failed (%s), returned byte slice does not match %x != %x",
				testNo, test.onErrorStr, test.expectedResult, result)
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
			Header{controlFieldEncode(PDURequestType, Version), 0x31, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
				NewTLVContainer([]byte{0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x01}, additionalHeaderDataLenMax)},
			nil,
			[]byte{0x20, 0xC4, 0x01, 0x04,
				0x00, 0x00,0x00,0x00,
				0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x01},
			"type:request, version:2, tid:0x31, cipher suite:0x01, pdu body offset: 16",
		},
		//Test case: 2
		{
			Header{controlFieldEncode(PDUResponseType, Version), 0x31, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			nil,
			[]byte{0xA0, 0xC4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			"type:response, version:2, tid:0x31, cipher suite:0x01, pdu body offset: 0",
		},
		// Test case: 3
		{
			Header{controlFieldEncode(PDURequestType, 4), 1, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
				NewTLVContainer([]byte{0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x01}, additionalHeaderDataLenMax)},
			nil,
			[]byte{0x40, 0x04, 0x01, 0x04,
				0x00,0x00,0x00,0x00,
				0x01, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x01,
				0x00, 0x00, 0x00, // slack
			},
			"type:request, version:4, tid:0x1, cipher suite:0x01, pdu body offset: 16",
		},
		// Test case: 4
		{
			Header{},
			nil,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			"encode empty header",
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

func BenchmarkHeaderMarshal(b *testing.B) {
	h := Header{
		CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
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
		CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
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

func TestHeaderUnmarshal(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedErr    error
		expectedResult Header
		onErrorStr     string
	}{
		// Test case: 1
		{
			[]byte{0x20, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{controlFieldEncode(PDURequestType, Version), 0x01, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			"type:request, version:2, tid:1, input of four bytes for version 1, request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 2
		{
			[]byte{0xA0, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{controlFieldEncode(PDUResponseType, 2), 0x01, CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256, nil},
			"type:response, version:2, tid:1, input of four bytes for version 1, request packet type with CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256",
		},
		// Test case: 3
		{
			[]byte{0xA0, 0x04, 0x01, 0x00},
			ErrHeaderTooShort,
			Header{},
			"missing reserved eBPF fields",
		},
		// Test case: 4
		{
			[]byte{0x20, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			ErrHeaderInvalid,
			Header{},
			"PDU Body Offset is greater than input data",
		},
		// Test case: 5
		{
			[]byte{0x20},
			ErrHeaderTooShort,
			Header{},
			"input byte of one",
		},
		// Test case: 6
		{
			[]byte{0x20, 0x04, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00},
			nil,
			Header{controlFieldEncode(PDURequestType, Version), 0x01, 0x3F, nil},
			"input of four bytes for version 1, request packet type with cipher suite 0x3F",
		},
		// Test case: 7
		{
			[]byte{0x20, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xFA, 0x12, 0xF0, 0xFF, 0xFF},
			ErrHeaderInvalid,
			Header{},
			"PDU body offset larger than available bytes in input",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result, err := headerUnmarshal(test.inputData)

		if test.expectedErr != err {
			t.Errorf("Test case: %d failed, returned error does not match, error:%v != error:%v",
				testNo, test.expectedErr, err)
		}

		if !test.expectedResult.Equal(result) {
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

func TestControlField(t *testing.T) {
	tests := []struct {
		inputPDUType      PDUType
		inputVersion    uint8
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

func randomBytes(size int) []byte {
	b := make([]byte, size)

	i , err := rand.Read(b)
	if i != size {
		panic(fmt.Sprintf("Failed to generate random bytes of size %d, generated only %d, err: %v", size, i, err))
	}

	if err != nil {
		panic(err)
	}
	return b
}