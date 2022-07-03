package openspalib

import (
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
