package openspalib

import (
	"net"
	"testing"
	"time"

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
	b, err := ProtocolEncode(ProtocolICMP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x01), b)
}

func TestProtocolEncode_TCP(t *testing.T) {
	b, err := ProtocolEncode(ProtocolTCP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x06), b)
}

func TestProtocolEncode_UDP(t *testing.T) {
	b, err := ProtocolEncode(ProtocolUDP)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x11), b)
}

func TestProtocolEncode_ICMPv6(t *testing.T) {
	b, err := ProtocolEncode(ProtocolICMPv6)
	assert.NoError(t, err)
	assert.Equal(t, byte(0x3A), b)
}

func TestProtocolDecode_ICMP(t *testing.T) {
	p, err := ProtocolDecode([]byte{0x01})
	assert.NoError(t, err)
	assert.Equal(t, InternetProtocolNumber(1), p)
}

func TestProtocolDecode_TCP(t *testing.T) {
	p, err := ProtocolDecode([]byte{0x06})
	assert.NoError(t, err)
	assert.Equal(t, InternetProtocolNumber(6), p)
}

func TestProtocolDecode_UDP(t *testing.T) {
	p, err := ProtocolDecode([]byte{0x11})
	assert.NoError(t, err)
	assert.Equal(t, InternetProtocolNumber(17), p)
}

func TestProtocolDecode_ICMPv6(t *testing.T) {
	p, err := ProtocolDecode([]byte{0x3a})
	assert.NoError(t, err)
	assert.Equal(t, InternetProtocolNumber(58), p)
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
		b, err := PortStartEncode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)

		b, err = PortEndEncode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestPortStartEndEncode_TooLargePort(t *testing.T) {
	b, err := PortStartEncode(65_536)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)

	b, err = PortStartEncode(65_536)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)
}
func TestPortStartEndEncode_TooLargePort2(t *testing.T) {
	b, err := PortStartEncode(65_537)
	assert.ErrorIs(t, err, ErrBadInput)
	assert.Nil(t, b)

	b, err = PortEndEncode(65_537)
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
		b, err := PortStartDecode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)

		b, err = PortEndDecode(test.input)
		assert.NoError(t, err)
		assert.Equal(t, test.expected, b)
	}
}

func TestPortStartEndDecode_TooLargePort(t *testing.T) {
	i, err := PortStartDecode([]byte{0x01, 0xFF, 0xFF})
	assert.ErrorIs(t, err, ErrInvalidBytes)
	assert.Equal(t, 0, i)

	i, err = PortEndDecode([]byte{0x01, 0xFF, 0xFF})
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
