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
