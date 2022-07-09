package openspalib

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimestampFromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", TimestampKey).Return([]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D}, true).Once()
	expect := time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC)

	tm, err := TimestampFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, expect, tm)

	c.AssertExpectations(t)
}

func TestTimestampToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetBytes", TimestampKey, []byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D}).Once()

	tm := time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC)
	err := TimestampToContainer(c, tm)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestProtocolFromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ProtocolKey).Return([]byte{0x06}, true).Once()
	expect := ProtocolTCP

	p, err := ProtocolFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, expect, p)

	c.AssertExpectations(t)
}

func TestProtocolToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetByte", ProtocolKey, byte(0x3A)).Once()

	err := ProtocolToContainer(c, ProtocolICMPv6)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPv4FromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{88, 200, 23, 9}, true).Once()
	expect := net.IPv4(88, 200, 23, 9)

	ip, err := ClientIPv4FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPv4ToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetBytes", ClientIPv4Key, []byte{88, 200, 23, 9}).Once()

	err := ClientIPv4ToContainer(c, net.IPv4(88, 200, 23, 9))
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestServerIPv4FromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ServerIPv4Key).Return([]byte{88, 200, 23, 9}, true).Once()
	expect := net.IPv4(88, 200, 23, 9)

	ip, err := ServerIPv4FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestServerIPv4ToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetBytes", ServerIPv4Key, []byte{88, 200, 23, 9}).Once()

	err := ServerIPv4ToContainer(c, net.IPv4(88, 200, 23, 9))
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPv6FromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ClientIPv6Key).Return([]byte(net.IPv6loopback), true).Once()
	expect := net.IPv6loopback

	ip, err := ClientIPv6FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPv6ToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetBytes", ClientIPv6Key, []byte(net.IPv6loopback)).Once()

	err := ClientIPv6ToContainer(c, net.IPv6loopback)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestServerIPv6FromContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ServerIPv6Key).Return([]byte(net.IPv6loopback), true).Once()
	expect := net.IPv6loopback

	ip, err := ServerIPv6FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestServerIPv6ToContainer(t *testing.T) {
	c := NewContainerMock()
	c.On("SetBytes", ServerIPv6Key, []byte(net.IPv6loopback)).Once()

	err := ServerIPv6ToContainer(c, net.IPv6loopback)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv4(t *testing.T) {
	c := NewContainerMock()
	expect := net.IPv4(88, 200, 23, 9).To4()
	c.On("GetBytes", ClientIPv4Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv6(t *testing.T) {
	c := NewContainerMock()
	expect := net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")
	c.On("GetBytes", ClientIPv6Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv4AndIPv6(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte(net.IPv4(88, 200, 23, 9).To4()), true).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte(net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")), true).Once()

	ip, err := ClientIPFromContainer(c)
	assert.ErrorIs(t, err, ErrViolationOfProtocolSpec)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_Empty(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{}, false).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.ErrorIs(t, err, ErrMissingEntry)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestServerIPFromContainer_IPv4(t *testing.T) {
	c := NewContainerMock()
	expect := net.IPv4(88, 200, 23, 9).To4()
	c.On("GetBytes", ServerIPv4Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ServerIPv6Key).Return([]byte{}, false).Once()

	ip, err := ServerIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestServerIPFromContainer_IPv6(t *testing.T) {
	c := NewContainerMock()
	expect := net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")
	c.On("GetBytes", ServerIPv6Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ServerIPv4Key).Return([]byte{}, false).Once()

	ip, err := ServerIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestServerIPFromContainer_IPv4AndIPv6(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ServerIPv4Key).Return([]byte(net.IPv4(88, 200, 23, 9).To4()), true).Once()
	c.On("GetBytes", ServerIPv6Key).Return([]byte(net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")), true).Once()

	ip, err := ServerIPFromContainer(c)
	assert.ErrorIs(t, err, ErrViolationOfProtocolSpec)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestServerIPFromContainer_Empty(t *testing.T) {
	c := NewContainerMock()
	c.On("GetBytes", ServerIPv4Key).Return([]byte{}, false).Once()
	c.On("GetBytes", ServerIPv6Key).Return([]byte{}, false).Once()

	ip, err := ServerIPFromContainer(c)
	assert.ErrorIs(t, err, ErrMissingEntry)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestNonceFromContainer(t *testing.T) {
	b := make([]byte, 3)
	rand.Read(b)

	c := NewContainerMock()
	c.On("GetBytes", NonceKey).Return(b, true).Once()

	n, err := NonceFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, b, n)

	c.AssertExpectations(t)
}

func TestNonceToContainer(t *testing.T) {
	b := make([]byte, 3)
	rand.Read(b)

	c := NewContainerMock()
	c.On("SetBytes", NonceKey, b).Once()

	err := NonceToContainer(c, b)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestDurationFromContainer(t *testing.T) {
	b, err := DurationEncode(time.Hour)
	assert.NoError(t, err)

	c := NewContainerMock()
	c.On("GetBytes", DurationKey).Return(b, true).Once()

	d, err := DurationFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, d, time.Hour)

	c.AssertExpectations(t)
}

func TestDurationToContainer(t *testing.T) {
	d := time.Hour
	b, err := DurationEncode(d)
	assert.NoError(t, err)

	c := NewContainerMock()
	c.On("SetBytes", DurationKey, b).Once()

	err = DurationToContainer(c, d)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}
