package request

import (
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/header"
	"net"
	"testing"
	"time"
)

func TestCreate(t *testing.T) {

	// The difference in time between when we create the
	// packet and when we test it
	const maxTimestampDelta = 10 // sec

	tests := []struct {
		inputData      New
		expectedErr    bool
		expectedResult Packet
		onErrorStr     string
	}{
		{
			New{
				"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.IPv4(88, 200, 23, 4),
				net.IPv4(88, 200, 23, 5),
				openspalib.EncryptionMethod_RSA2048_AES256CBC,
			},
			false,
			Packet{
				header.Header{
					openspalib.Version,
					true,
					openspalib.EncryptionMethod_RSA2048_AES256CBC,
				},
				packetPayload{
					time.Now(),
					"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
					[]byte{0x00, 0x00, 0x00}, // we do not check this, since it should be cryptographically random
					openspalib.Protocol_TCP,
					80,
					80,
					openspalib.SignatureMethod_RSA_SHA256,
					false,
					net.IPv4(88, 200, 23, 4),
					net.IPv4(88, 200, 23, 5),
				},
				[]byte{},
				[]byte{},
				[]byte{},
			},
			"failed to create packet struct using valid values",
		},

		{
			New{
				"8f97e69c-1bb1-4d2f",
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.IPv4(88, 200, 23, 4),
				net.IPv4(88, 200, 23, 5),
				openspalib.EncryptionMethod_RSA2048_AES256CBC,
			},
			true,
			Packet{},
			"failed to return error when creating packet using a bad client device ID",
		},
		{
			New{
				"8f97e69c1bb14d2f8cb024f2e874254d",
				openspalib.Protocol_TCP,
				80,
				0,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.IPv4(88, 200, 23, 4),
				net.IPv4(88, 200, 23, 5),
				openspalib.EncryptionMethod_RSA2048_AES256CBC,
			},
			true,
			Packet{},
			"failed to return error when creating packet using part 0 for the end port",
		},
		{
			New{
				"8f97e69c1bb14d2f8cb024f2e874254d",
				openspalib.Protocol_TCP,
				80,
				80,
				255,
				false,
				net.IPv4(88, 200, 23, 4),
				net.IPv4(88, 200, 23, 5),
				openspalib.EncryptionMethod_RSA2048_AES256CBC,
			},
			true,
			Packet{},
			"failed to return error when creating packet using an unsupported signature method",
		},
		{
			New{
				"8f97e69c1bb14d2f8cb024f2e874254d",
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.IPv4(88, 200, 23, 4),
				net.IPv4(88, 200, 23, 5),
				255,
			},
			true,
			Packet{},
			"failed to return error when creating packet using an unsupported encryption method",
		},
		{
			New{
				"8f97e69c1bb14d2f8cb024f2e874254d",
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				true,
				net.IPv4(88, 200, 23, 4),
				net.ParseIP("2a02:7a8:1:250::80:1"),
				255,
			},
			true,
			Packet{
				header.Header{
					openspalib.Version,
					true,
					openspalib.EncryptionMethod_RSA2048_AES256CBC,
				},
				packetPayload{
					time.Now(),
					"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
					[]byte{0x00, 0x00, 0x00}, // we do not check this, since it should be cryptographically random
					openspalib.Protocol_TCP,
					80,
					80,
					openspalib.SignatureMethod_RSA_SHA256,
					true,
					net.IPv4(88, 200, 23, 4),
					net.ParseIP("2a02:7a8:1:250::80:1"),
				},
				[]byte{},
				[]byte{},
				[]byte{},
			},
			"failed to create packet using a client public IPv4 address and server public IPv6 address with the client behind NAT flag to true",
		},
	}

	for i, test := range tests {
		result, err := test.inputData.Create()

		if err != nil != test.expectedErr {
			t.Errorf("unexpected error or lack of one, test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		// skip the testing since we already returned an error
		if test.expectedErr {
			continue
		}

		// Header test
		if result.Header != test.expectedResult.Header {
			t.Errorf("Expected different header on test case: %d, %v != %v, reason: %s",
				i, result.Header, test.expectedResult.Header, test.onErrorStr)
		}

		// Timestamp test
		timestampDelta := time.Now().Unix() - result.Payload.Timestamp.Unix()
		if timestampDelta > maxTimestampDelta {
			t.Errorf("Timestamp is greater than the timestamp testing delta on test case:%d, delta: %d, reason: %s",
				i, timestampDelta, test.onErrorStr)
		}

		// Client Device ID test
		resultDeviceID := result.Payload.ClientDeviceID
		expectedDeviceID := test.expectedResult.Payload.ClientDeviceID

		if resultDeviceID != expectedDeviceID {
			t.Errorf("Expected different client device ID on test case: %d, %v != %v, reason: %s",
				i, resultDeviceID, expectedDeviceID, test.onErrorStr)
		}

		// Check to see that the nonce is not empty this test "could" fail if the generated Nonce
		// is [0x00, 0x00, 0x00]. However the probability of this happening is (1/2^8)^3 = 5.96 * 10^-8.
		resultNonce := result.Payload.Nonce
		if resultNonce[0] == 0x00 && resultNonce[1] == 0x00 && resultNonce[2] == 0x00 {
			t.Errorf("Generated nonce is not random (it's all zeros), test case: %d, reason: %s",
				i, test.onErrorStr)
		}

		// Protocol test
		resultProtocol := result.Payload.Protocol
		expectedProtocol := test.expectedResult.Payload.Protocol
		if resultProtocol != expectedProtocol {
			t.Errorf("Expected different protocol on test case: %d, %v != %v, reason: %s",
				i, resultProtocol, expectedProtocol, test.onErrorStr)
		}

		// Start Port test
		resultStartPort := result.Payload.StartPort
		expectedStartPort := test.expectedResult.Payload.StartPort
		if resultStartPort != expectedStartPort {
			t.Errorf("Expected different start port on test case: %d, %v != %v, reason: %s",
				i, resultStartPort, expectedStartPort, test.onErrorStr)
		}

		// End Port test
		resultEndPort := result.Payload.EndPort
		expectedEndPort := test.expectedResult.Payload.EndPort
		if resultEndPort != expectedEndPort {
			t.Errorf("Expected different end port on test case: %d, %v != %v, reason: %s",
				i, resultEndPort, expectedEndPort, test.onErrorStr)
		}

		// Signature Method test
		resultSigMeth := result.Payload.SignatureMethod
		expectedSigMeth := test.expectedResult.Payload.SignatureMethod
		if resultSigMeth != expectedSigMeth {
			t.Errorf("Expected different signature method on test case: %d, %v != %v, reason: %s",
				i, resultSigMeth, expectedSigMeth, test.onErrorStr)
		}

		// Client Behind NAT test
		resultClientNAT := result.Payload.ClientBehindNat
		expectedClientNAT := test.expectedResult.Payload.ClientBehindNat
		if resultClientNAT != expectedClientNAT {
			t.Errorf("Expected different value for client behind NAT on test case: %d, %v != %v, reason: %s",
				i, resultClientNAT, expectedClientNAT, test.onErrorStr)
		}

		// Client Public IP test
		resultClientPubIP := result.Payload.ClientPublicIP
		expectedClientPubIP := test.expectedResult.Payload.ClientPublicIP
		if !resultClientPubIP.Equal(expectedClientPubIP) {
			t.Errorf("Expected different client public IP on test case: %d, %v != %v, reason: %s",
				i, resultClientPubIP, expectedClientPubIP, test.onErrorStr)
		}

		// Server Public IP test
		resultServerPubIP := result.Payload.ServerPublicIP
		expectedServerPubIP := test.expectedResult.Payload.ServerPublicIP
		if !resultServerPubIP.Equal(expectedServerPubIP) {
			t.Errorf("Expected different Server public IP on test case: %d, %v != %v, reason: %s",
				i, resultServerPubIP, expectedServerPubIP, test.onErrorStr)
		}

	}
}

func TestPacket_Export(t *testing.T) {
	// TODO
}
