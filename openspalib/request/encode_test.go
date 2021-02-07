package request

import (
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/tools"
	"net"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		inputData      packetPayload
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		{
			packetPayload{
				time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
				"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				[]byte{0x64, 0x8A, 0x0C},
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.IPv4(193, 2, 1, 15),
				net.IPv4(193, 2, 1, 66),
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
				0x01,       // Signature Method
				0x00,       // Misc field
				0x00, 0x00, // Reserved
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client Public IP
				0x00, 0x00, 0xFF, 0xFF, 0xC1, 0x02, 0x01, 0x0F, // Client Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Server Public IP
				0x00, 0x00, 0xFF, 0xFF, 0xC1, 0x02, 0x01, 0x42, // Server Public IP
			},
			"failed to encode a client OpenSPA request, the client is not behind a NAT",
		},
		{
			packetPayload{
				time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
				"8f97e69c-1bb1-4d2f-8cb0-24f2e874254d",
				[]byte{0x64, 0x8A, 0x0C},
				openspalib.Protocol_TCP,
				80,
				80,
				openspalib.SignatureMethod_RSA_SHA256,
				false,
				net.ParseIP("2001:1470:8000::72"),
				net.ParseIP("2a02:7a8:1:250::80:1"),
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
				0x01,       // Signature Method
				0x00,       // Misc field
				0x00, 0x00, // Reserved
				0x20, 0x01, 0x14, 0x70, 0x80, 0x00, 0x00, 0x00, // Client Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, // Client Public IP
				0x2a, 0x02, 0x07, 0xa8, 0x00, 0x01, 0x02, 0x50, // Server Public IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x01, // Server Public IP
			},
			"failed to encode a client OpenSPA request, the client is not behind a NAT",
		},
	}

	for i, test := range tests {
		result, err := test.inputData.Encode()

		if err != nil != test.expectedErr {
			t.Errorf("test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

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

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
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

func TestEncodeMiscField(t *testing.T) {
	tests := []struct {
		inputDataBehindNAT bool
		expectedResult     byte
		onErrorStr         string
	}{
		{
			true,
			0x80,
			"failed to encode with the client behind NAT set to true",
		},
		{
			false,
			0x00,
			"failed to encode with the client behind NAT set to false",
		},
	}

	for i, test := range tests {
		result := encodeMiscField(test.inputDataBehindNAT)

		if result != test.expectedResult {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}

func TestIPAddressToBinIP(t *testing.T) {
	tests := []struct {
		inputData      net.IP
		expectedErr    bool
		expectedResult []byte
		onErrorStr     string
	}{
		{
			net.IPv4(8, 8, 8, 8),
			false,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				0xFF, 0x08, 0x08, 0x08, 0x08},
			"failed to encode 8.8.8.8",
		},
		{
			net.IPv4(193, 2, 1, 66),
			false,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				0xFF, 0xC1, 0x02, 0x01, 0x42},
			"failed to encode 193.2.1.66",
		},
		{
			net.IPv4(193, 2, 1, 72),
			false,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				0xFF, 0xC1, 0x02, 0x01, 0x48},
			"failed to encode 193.2.1.72",
		},
		{
			net.IPv4(212, 235, 188, 20),
			false,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
				0xFF, 0xD4, 0xEB, 0xBC, 0x14},
			"failed to encode 212.235.188.20",
		},
		{
			net.ParseIP("2001:1470:8000::66"),
			false,
			[]byte{0x20, 0x01, 0x14, 0x70, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x66},
			"failed to encode 2001:1470:8000::66",
		},
		{
			net.ParseIP("2001:1470:8000::72"),
			false,
			[]byte{0x20, 0x01, 0x14, 0x70, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x72},
			"failed to encode 2001:1470:8000::72",
		},
		{
			net.ParseIP("2a02:7a8:1:250::80:1"),
			false,
			[]byte{0x2a, 0x02, 0x07, 0xa8, 0x00, 0x01, 0x02, 0x50, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x80, 0x00, 0x01},
			"failed to encode 2a02:7a8:1:250::80:1",
		},
	}

	for i, test := range tests {
		result, err := IPAddressToBinIP(test.inputData)

		if err != nil != test.expectedErr {
			t.Errorf("test case: %d, reason: %s, error: %s", i, test.onErrorStr, err)
			continue
		}

		if !tools.CompareTwoByteSlices(result, test.expectedResult) {
			t.Errorf("Test case: %d, %v != %v, reason: %s", i, result, test.expectedResult, test.onErrorStr)
		}
	}
}
