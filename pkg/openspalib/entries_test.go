package openspalib

import (
	"net"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestTimestampEncode(t *testing.T) {
	tests := []struct {
		inputData      time.Time
		expectedResult []byte
	}{
		{
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
		},
		{
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
		},
		{
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
		},
		{
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
		},
	}

	for _, test := range tests {
		result, err := TimestampEncode(test.inputData)
		assert.NoError(t, err)
		assert.Equal(t, test.expectedResult, result)
	}
}

func TestTimestampDecode(t *testing.T) {
	tests := []struct {
		inputData      []byte
		expectedResult time.Time
	}{
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D},
			time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0x71, 0xDD, 0x70, 0xDD},
			time.Date(2030, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		{
			[]byte{0x00, 0x00, 0x00, 0x00, 0xAA, 0x4C, 0x05, 0xDD},
			time.Date(2060, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		{
			[]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D},
			time.Date(3018, 7, 15, 9, 22, 37, 0, time.UTC),
		},
		{
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			time.Unix(0, 0).UTC(),
		},
	}

	for _, test := range tests {
		result, err := TimestampDecode(test.inputData)
		assert.NoError(t, err)
		assert.Equal(t, test.expectedResult, result)
	}
}

func TestTimestampDecode_EmptyBytes(t *testing.T) {
	_, err := TimestampDecode([]byte{})
	assert.ErrorIs(t, err, ErrInvalidBytes)
}

func TestTimestampDecode_NotEnoughBytes(t *testing.T) {
	_, err := TimestampDecode([]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49})
	assert.ErrorIs(t, err, ErrInvalidBytes)
}

func TestTimestampDecode_TooManyBytes(t *testing.T) {
	_, err := TimestampDecode([]byte{0x00, 0x00, 0x00, 0x07, 0xB4, 0x3B, 0x49, 0x5D, 0x42})
	assert.ErrorIs(t, err, ErrInvalidBytes)
}

func TestProtocolEncode_ICMP(t *testing.T) {
	b, err := TargetProtocolEncode(ProtocolICMP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x01), b)
}

func TestProtocolEncode_TCP(t *testing.T) {
	b, err := TargetProtocolEncode(ProtocolTCP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x06), b)
}

func TestProtocolEncode_UDP(t *testing.T) {
	b, err := TargetProtocolEncode(ProtocolUDP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x11), b)
}

func TestProtocolEncode_ICMPv6(t *testing.T) {
	b, err := TargetProtocolEncode(ProtocolICMPv6)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x3A), b)
}

func TestProtocolDecode_ICMP(t *testing.T) {
	p, err := TargetProtocolDecode([]byte{0x01})
	assert.NoError(t, err)
	assert.Equal(t, ProtocolICMP, p)
}

func TestProtocolDecode_TCP(t *testing.T) {
	p, err := TargetProtocolDecode([]byte{0x06})
	assert.NoError(t, err)
	assert.Equal(t, ProtocolTCP, p)
}

func TestProtocolDecode_UDP(t *testing.T) {
	p, err := TargetProtocolDecode([]byte{0x11})
	assert.NoError(t, err)
	assert.Equal(t, ProtocolUDP, p)
}

func TestProtocolDecode_ICMPv6(t *testing.T) {
	p, err := TargetProtocolDecode([]byte{0x3a})
	assert.NoError(t, err)
	assert.Equal(t, ProtocolICMPv6, p)
}

func TestPortStartEndEncode(t *testing.T) {
	tests := []struct {
		input    int
		expected []byte
	}{
		{
			input:    80,
			expected: []byte{0, 80},
		},
		{
			input:    0,
			expected: []byte{0, 0},
		},
		{
			input:    8080,
			expected: []byte{0x1F, 0x90},
		},
		{
			input:    65_535,
			expected: []byte{0xFF, 0xFF},
		},
		{
			input:    65_534,
			expected: []byte{0xFF, 0xFE},
		},
	}

	for _, test := range tests {
		b, err := TargetPortStartEncode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)

		b, err = TargetPortEndEncode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestPortStartEndEncode_TooLargePort(t *testing.T) {
	b, err := TargetPortStartEncode(65_536)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)

	b, err = TargetPortStartEncode(65_536)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)
}
func TestPortStartEndEncode_TooLargePort2(t *testing.T) {
	b, err := TargetPortStartEncode(65_537)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)

	b, err = TargetPortEndEncode(65_537)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)
}

func TestPortStartEndDecode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int
	}{
		{
			input:    []byte{80},
			expected: 80,
		},
		{
			input:    []byte{0, 80},
			expected: 80,
		},
		{
			input:    []byte{0, 0},
			expected: 0,
		},
		{
			input:    []byte{0x1F, 0x90},
			expected: 8080,
		},
		{
			input:    []byte{0xFF, 0xFF},
			expected: 65_535,
		},
		{
			input:    []byte{0xFF, 0xFE},
			expected: 65_534,
		},
	}

	for _, test := range tests {
		b, err := TargetPortStartDecode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)

		b, err = TargetPortEndDecode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestPortStartEndDecode_TooLargePort(t *testing.T) {
	i, err := TargetPortStartDecode([]byte{0x01, 0xFF, 0xFF})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, 0, i)

	i, err = TargetPortEndDecode([]byte{0x01, 0xFF, 0xFF})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, 0, i)
}

func TestIPv4Encode(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected []byte
	}{
		{
			input:    net.IPv4(192, 168, 1, 2),
			expected: []byte{192, 168, 1, 2},
		},
		{
			input:    net.IPv4(127, 0, 0, 1),
			expected: []byte{127, 0, 0, 1},
		},
		{
			input:    net.IPv4(1, 0, 0, 1),
			expected: []byte{1, 0, 0, 1},
		},
		{
			input:    net.IPv4(1, 0, 0, 1).To4(),
			expected: []byte{1, 0, 0, 1},
		},
	}

	for _, test := range tests {
		b, err := IPv4Encode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestIPv4Encode_IPv6Address(t *testing.T) {
	ip, err := IPv4Encode(net.IPv6loopback)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, ip)
}

func TestIPv4Encode_Nil(t *testing.T) {
	ip, err := IPv4Encode(nil)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, ip)
}

func TestIPv4Decode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected net.IP
	}{
		{
			input:    []byte{192, 168, 1, 2},
			expected: net.IPv4(192, 168, 1, 2).To4(),
		},
		{
			input:    []byte{127, 0, 0, 1},
			expected: net.IPv4(127, 0, 0, 1).To4(),
		},
		{
			input:    []byte{1, 0, 0, 1},
			expected: net.IPv4(1, 0, 0, 1).To4(),
		},
	}

	for _, test := range tests {
		b, err := IPv4Decode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestIPv4Decode_IPv6Address(t *testing.T) {
	ip, err := IPv4Decode([]byte(net.IPv6loopback))
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Nil(t, ip)
}

func TestIPv4Decode_Nil(t *testing.T) {
	ip, err := IPv4Decode(nil)
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Nil(t, ip)
}

func TestIPv6Encode(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected []byte
	}{
		{
			input:    net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f"),
			expected: []byte{0x20, 0x01, 0x14, 0x70, 0xff, 0xfd, 0x20, 0x73, 0x02, 0x50, 0x56, 0xff, 0xfe, 0x81, 0x74, 0x1f},
		},
		{
			input:    net.IPv6loopback,
			expected: []byte(net.IPv6loopback),
		},
	}

	for _, test := range tests {
		b, err := IPv6Encode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestIPv6Encode_IPv4Address(t *testing.T) {
	ip, err := IPv6Encode(net.IPv4(88, 200, 23, 9))
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, ip)
}

func TestIPv6Encode_IPv4Address2(t *testing.T) {
	ip, err := IPv6Encode(net.IPv4(88, 200, 23, 9).To4())
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, ip)
}

func TestIPv6Encode_Nil(t *testing.T) {
	ip, err := IPv6Encode(nil)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, ip)
}

func TestIPv6Decode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected net.IP
	}{
		{
			input:    []byte{0x20, 0x01, 0x14, 0x70, 0xff, 0xfd, 0x20, 0x73, 0x02, 0x50, 0x56, 0xff, 0xfe, 0x81, 0x74, 0x1f},
			expected: net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f"),
		},
		{
			input:    []byte(net.IPv6loopback),
			expected: net.IPv6loopback,
		},
	}

	for _, test := range tests {
		b, err := IPv6Decode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestIPv6Decode_IPv4Address(t *testing.T) {
	ip, err := IPv6Decode([]byte(net.IPv4(88, 200, 23, 9).To4()))
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Nil(t, ip)
}

func TestIPv6Decode_Nil(t *testing.T) {
	ip, err := IPv6Decode(nil)
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Nil(t, ip)
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected bool
	}{
		{
			input:    net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f"),
			expected: false,
		},
		{
			input:    net.IPv6loopback,
			expected: false,
		},
		{
			input:    net.IPv4allrouter,
			expected: true,
		},
		{
			input:    net.IPv4(127, 0, 0, 1),
			expected: true,
		},
	}

	for _, test := range tests {
		b := isIPv4(test.input)
		assert.Equal(t, test.expected, b)
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected bool
	}{
		{
			input:    net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f"),
			expected: true,
		},
		{
			input:    net.IPv6loopback,
			expected: true,
		},
		{
			input:    net.IPv4allrouter,
			expected: false,
		},
		{
			input:    net.IPv4(127, 0, 0, 1),
			expected: false,
		},
	}

	for _, test := range tests {
		b := isIPv6(test.input)
		assert.Equal(t, test.expected, b)
	}
}

func TestDurationEncode(t *testing.T) {
	b, err := DurationEncode(10 * time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x02, 0x58}, b)
}

func TestDurationEncode_TooSmallDuration(t *testing.T) {
	b, err := DurationEncode(100 * time.Millisecond)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)
}

func TestDurationEncode_TooLargeDuration(t *testing.T) {
	b, err := DurationEncode(200 * 24 * time.Hour)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)
}

func TestDurationDecode(t *testing.T) {
	expect := 10 * time.Minute
	d, err := DurationDecode([]byte{0x00, 0x02, 0x58})
	assert.NoError(t, err)
	assert.Equal(t, expect, d)
}

func TestDurationDecode_TooLarge(t *testing.T) {
	d, err := DurationDecode([]byte{0x02, 0x58, 0x00, 0x00})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, time.Duration(0), d)
}

func TestDurationDecode_TooShort(t *testing.T) {
	d, err := DurationDecode([]byte{0x02, 0x58})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, time.Duration(0), d)
}

func TestDurationDecode_Nil(t *testing.T) {
	d, err := DurationDecode(nil)
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, time.Duration(0), d)
}

func TestClientUUIDEncode(t *testing.T) {
	u := uuid.NewV4()

	b, err := ClientUUIDEncode(u.String())
	assert.NoError(t, err)
	assert.Equal(t, u.Bytes(), b)
}

func TestClientUUIDEncode_InvalidUUID(t *testing.T) {
	b, err := ClientUUIDEncode("foo-bar")
	assert.Error(t, err)
	assert.Nil(t, b)
}

func TestClientUUIDEncode_WithDashes(t *testing.T) {
	b, err := ClientUUIDEncode("54141264-9c0c-4e61-8825-bf19a736d527")
	assert.NoError(t, err)

	target := []byte{
		0x54,
		0x14,
		0x12,
		0x64,
		0x9c,
		0x0c,
		0x4e,
		0x61,
		0x88,
		0x25,
		0xbf,
		0x19,
		0xa7,
		0x36,
		0xd5,
		0x27,
	}

	assert.Equal(t, target, b)
}

func TestClientUUIDDecode(t *testing.T) {
	b := []byte{
		0x54,
		0x14,
		0x12,
		0x64,
		0x9c,
		0x0c,
		0x4e,
		0x61,
		0x88,
		0x25,
		0xbf,
		0x19,
		0xa7,
		0x36,
		0xd5,
		0x27,
	}
	id, err := ClientUUIDDecode(b)
	assert.NoError(t, err)
	assert.Equal(t, "54141264-9c0c-4e61-8825-bf19a736d527", id)
}

func TestClientUUIDDecode_TooShort(t *testing.T) {
	id, err := ClientUUIDDecode([]byte{0x02, 0x58})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, "", id)
}

func TestClientUUIDDecode_Nil(t *testing.T) {
	id, err := ClientUUIDDecode(nil)
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, "", id)
}
