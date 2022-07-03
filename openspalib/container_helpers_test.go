package openspalib

import (
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
