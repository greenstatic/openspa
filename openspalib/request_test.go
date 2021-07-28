package openspalib

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestRequestBodyEncode(t *testing.T) {
	tests := []struct {
		inputData      RequestBody
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		{
			RequestBody{
				Timestamp:       time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
				ClientDeviceID:  "8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				Nonce:           []byte{0x64, 0x8A, 0x0C},
				Protocol:        ProtocolTCP,
				StartPort:       80,
				EndPort:         80,
				ClientBehindNat: false,
				ClientPublicIP:  net.IPv4(193, 2, 1, 15),
				ServerPublicIP:  net.IPv4(193, 2, 1, 66),
				TlvValues: nil,
			},
			false,
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D, // Timestamp
				0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, // Client Device ID
				0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74, 0x25, 0x4D, // Client Device ID
				0x64, 0x8A, 0x0C, // Nonce
				0x06,       // Protocol
				0x00, 0x50, // Start Port
				0x00, 0x50, // End Port
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client Public IP
				0x00, 0x00, 0xFF, 0xFF, 0xC1, 0x02, 0x01, 0x0F, // Client Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Server Public IP
				0x00, 0x00, 0xFF, 0xFF, 0xC1, 0x02, 0x01, 0x42, // Server Public IP
				0x00, 0x00, 0x00, 0x00, // Misc field

			},
			"failed to encode a client OpenSPA request, the client is not behind a NAT",
		},
		{
			RequestBody{
				Timestamp:       time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
				ClientDeviceID:  "8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				Nonce:           []byte{0x64, 0x8A, 0x0C},
				Protocol:        ProtocolTCP,
				StartPort:       80,
				EndPort:         80,
				ClientBehindNat: false,
				ClientPublicIP:  net.ParseIP("2001:1470:8000::72"),
				ServerPublicIP:  net.ParseIP("2a02:7a8:1:250::80:1"),
				TlvValues: nil, // TODO - fix
			},
			false,
			[]byte{
				0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D, // Timestamp
				0x8F, 0x97, 0xE6, 0x9C, 0x1B, 0xB1, 0x4D, 0x2F, // Client Device ID
				0x8C, 0xB0, 0x24, 0xF2, 0xE8, 0x74, 0x25, 0x4D, // Client Device ID
				0x64, 0x8A, 0x0C, // Nonce
				0x06,       // Protocol
				0x00, 0x50, // Start Port
				0x00, 0x50, // End Port
				0x20, 0x01, 0x14, 0x70, 0x80, 0x00, 0x00, 0x00, // Client Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, // Client Public IP
				0x2a, 0x02, 0x07, 0xa8, 0x00, 0x01, 0x02, 0x50, // Server Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x01, // Server Public IP
				0x00, 0x00, 0x00, 0x00, // Misc field
			},
			"failed to encode a client OpenSPA request, the client is not behind a NAT",
		},
	}

	for i, test := range tests {
		result, err := requestBodyMarshal(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		if !bytes.Equal(result, test.expectedResult) {
			t.Errorf("test case: %d: \n%v\n != \n%v\n reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestNewRequest(t *testing.T) {
	// The difference in time between when we create the packet and when we test it
	const maxTimestampDelta = 10 // sec

	tests := []struct {
		inputData      RequestData
		inputCipherSuite CipherSuiteId
		expectedErr    bool
		expectedResult Request
		onErrorStr     string
	}{
		// Test case: 1
		{
			RequestData{
				ClientDeviceID:   "8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          80,
				ClientBehindNat:  false,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.IPv4(88, 200, 23, 5),
			},
			CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			false,
			Request{
				Head: Header{
					controlField: controlFieldEncode(PDURequestType, Version),
					CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
				},
				Body: RequestBody{
					Timestamp:       time.Now(),
					ClientDeviceID:  "8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
					Nonce:           []byte{0x00, 0x00, 0x00}, // we do not check this, since it should be cryptographically random
					Protocol:        ProtocolTCP,
					StartPort:       80,
					EndPort:         80,
					ClientBehindNat: false,
					ClientPublicIP:  net.IPv4(88, 200, 23, 4),
					ServerPublicIP:  net.IPv4(88, 200, 23, 5),
				},
				Signature: []byte{},
			},
			"failed to create packet struct using valid values",
		},
		// Test case: 2
		{
			RequestData{
				ClientDeviceID:   "8f97e69c-1bb1-4d2f",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          80,
				ClientBehindNat:  false,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.IPv4(88, 200, 23, 5),
			},
			CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			true,
			Request{},
			"failed to return error when creating packet using a bad client device ID",
		},
		// Test case: 3
		{
			RequestData{
				ClientDeviceID:   "8f97e69c1bb14d2f8cb024f2e874254d",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          0,
				ClientBehindNat:  false,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.IPv4(88, 200, 23, 5),
			},
			CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			true,
			Request{},
			"failed to return error when creating packet using part 0 for the end port",
		},
		// Test case: 4
		{
			RequestData{
				ClientDeviceID:   "8f97e69c1bb14d2f8cb024f2e874254d",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          80,
				ClientBehindNat:  false,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.IPv4(88, 200, 23, 5),
			},
			0x23,
			true,
			Request{},
			"failed to return error when creating packet using an unsupported cipher suite",
		},
		// Test case: 5
		{
			RequestData{
				ClientDeviceID:   "8f97e69c1bb14d2f8cb024f2e874254d",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          80,
				ClientBehindNat:  false,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.IPv4(88, 200, 23, 5),
			},
			0x55,
			true,
			Request{},
			"failed to return error when creating packet using an unsupported cipher suite",
		},
		// Test case: 6
		{
			RequestData{
				ClientDeviceID:   "8f97e69c1bb14d2f8cb024f2e874254d",
				Protocol:         ProtocolTCP,
				StartPort:        80,
				EndPort:          80,
				ClientBehindNat:  true,
				ClientPublicIP:   net.IPv4(88, 200, 23, 4),
				ServerPublicIP:   net.ParseIP("2a02:7a8:1:250::80:1"),
			},
			CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
			false,
			Request{
				Head: Header{
					controlField: controlFieldEncode(PDURequestType, Version),
					CipherSuite: CipherSuite_RSA_AES_128_CBC_WITH_RSA_SHA256,
					AdditionalHeaderData: nil,
				},
				Body: RequestBody{
					Timestamp:       time.Now(),
					ClientDeviceID:  "8f97e69c1bb14d2f8cb024f2e874254d",
					Nonce:           []byte{0x00, 0x00, 0x00}, // we do not check this, since it should be cryptographically random
					Protocol:        ProtocolTCP,
					StartPort:       80,
					EndPort:         80,
					ClientBehindNat: true,
					ClientPublicIP:  net.IPv4(88, 200, 23, 4),
					ServerPublicIP:  net.ParseIP("2a02:7a8:1:250::80:1"),
				},
				Signature: []byte{},
			},
			"failed to create packet using a client public IPv4 address and server public IPv6 address with the client behind NAT flag to true",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		request, err := CraftRequest(test.inputData, test.inputCipherSuite)
		if err != nil != test.expectedErr {
			t.Errorf("unexpected error or lack of one, test case: %d, reason: %s, error: %v", testNo, test.onErrorStr, err)
			continue
		}

		// skip the testing since we already returned an error
		if test.expectedErr {
			continue
		}

		if request == nil {
			t.Errorf("unexpected error, request is nil, test case: %d", testNo)
			continue
		}

		// Header test
		if !request.Head.Equal(test.expectedResult.Head) {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				testNo, request.Head, test.expectedResult.Head, test.onErrorStr)
		}

		// Timestamp test
		timestampDelta := time.Now().Unix() - request.Body.Timestamp.Unix()
		if timestampDelta > maxTimestampDelta {
			t.Errorf("Timestamp is greater than the timestamp testing delta on test case:%d, delta: %d, reason: %s",
				testNo, timestampDelta, test.onErrorStr)
		}

		// Client Device ID test
		resultDeviceID := request.Body.ClientDeviceID
		expectedDeviceID := test.expectedResult.Body.ClientDeviceID

		if resultDeviceID != expectedDeviceID {
			t.Errorf("Expected different client device ID on test case: %d, %v != %v, reason: %s",
				testNo, resultDeviceID, expectedDeviceID, test.onErrorStr)
		}

		// Check to see that the nonce is not empty this test "could" fail if the generated Nonce
		// is [0x00, 0x00, 0x00]. However the probability of this happening is (1/2^8)^3 = 5.96 * 10^-8.
		resultNonce := request.Body.Nonce
		if resultNonce[0] == 0x00 && resultNonce[1] == 0x00 && resultNonce[2] == 0x00 {
			t.Errorf("Generated nonce is not random (it's all zeros), test case: %d, reason: %s",
				testNo, test.onErrorStr)
		}

		// Protocol test
		resultProtocol := request.Body.Protocol
		expectedProtocol := test.expectedResult.Body.Protocol
		if resultProtocol != expectedProtocol {
			t.Errorf("Expected different protocol on test case: %d, %v != %v, reason: %s",
				testNo, resultProtocol, expectedProtocol, test.onErrorStr)
		}

		// Start Port test
		resultStartPort := request.Body.StartPort
		expectedStartPort := test.expectedResult.Body.StartPort
		if resultStartPort != expectedStartPort {
			t.Errorf("Expected different start port on test case: %d, %v != %v, reason: %s",
				testNo, resultStartPort, expectedStartPort, test.onErrorStr)
		}

		// End Port test
		resultEndPort := request.Body.EndPort
		expectedEndPort := test.expectedResult.Body.EndPort
		if resultEndPort != expectedEndPort {
			t.Errorf("Expected different end port on test case: %d, %v != %v, reason: %s",
				testNo, resultEndPort, expectedEndPort, test.onErrorStr)
		}

		// Client Behind NAT test
		resultClientNAT := request.Body.ClientBehindNat
		expectedClientNAT := test.expectedResult.Body.ClientBehindNat
		if resultClientNAT != expectedClientNAT {
			t.Errorf("Expected different value for client behind NAT on test case: %d, %v != %v, reason: %s",
				testNo, resultClientNAT, expectedClientNAT, test.onErrorStr)
		}

		// Client Public IP test
		resultClientPubIP := request.Body.ClientPublicIP
		expectedClientPubIP := test.expectedResult.Body.ClientPublicIP
		if !resultClientPubIP.Equal(expectedClientPubIP) {
			t.Errorf("Expected different client public IP on test case: %d, %v != %v, reason: %s",
				testNo, resultClientPubIP, expectedClientPubIP, test.onErrorStr)
		}

		// Server Public IP test
		resultServerPubIP := request.Body.ServerPublicIP
		expectedServerPubIP := test.expectedResult.Body.ServerPublicIP
		if !resultServerPubIP.Equal(expectedServerPubIP) {
			t.Errorf("Expected different Server public IP on test case: %d, %v != %v, reason: %s",
				testNo, resultServerPubIP, expectedServerPubIP, test.onErrorStr)
		}

	}
}
