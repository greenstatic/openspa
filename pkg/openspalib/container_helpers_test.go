package openspalib

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestTimestampFromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TimestampKey).Return([]byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D}, true).Once()
	expect := time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC)

	tm, err := TimestampFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, expect, tm)

	c.AssertExpectations(t)
}

func TestTimestampToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", TimestampKey, []byte{0x00, 0x00, 0x00, 0x00, 0x5B, 0x4B, 0x12, 0x5D}).Once()

	tm := time.Date(2018, 7, 15, 9, 22, 37, 0, time.UTC)
	err := TimestampToContainer(c, tm)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestTargetProtocolFromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetProtocolKey).Return([]byte{0x06}, true).Once()
	expect := ProtocolTCP

	p, err := TargetProtocolFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, expect, p)

	c.AssertExpectations(t)
}

func TestTargetProtocolToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetByte", TargetProtocolKey, byte(0x3A)).Once()

	err := TargetProtocolToContainer(c, ProtocolICMPv6)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestTargetPortStartFromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetPortStartKey).Return([]byte{0x1F, 0x90}, true).Once()

	p, err := TargetPortStartFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, 8080, p)

	c.AssertExpectations(t)
}

func TestTargetPortStartToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", TargetPortStartKey, []byte{0x1F, 0x90}).Once()

	err := TargetPortStartToContainer(c, 8080)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestTargetPortEndFromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetPortEndKey).Return([]byte{0x1F, 0x90}, true).Once()

	p, err := TargetPortEndFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, 8080, p)

	c.AssertExpectations(t)
}

func TestTargetPortEndToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", TargetPortEndKey, []byte{0x1F, 0x90}).Once()

	err := TargetPortEndToContainer(c, 8080)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPv4FromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{88, 200, 23, 9}, true).Once()
	expect := net.IPv4(88, 200, 23, 9)

	ip, err := ClientIPv4FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPv4ToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", ClientIPv4Key, []byte{88, 200, 23, 9}).Once()

	err := ClientIPv4ToContainer(c, net.IPv4(88, 200, 23, 9))
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestTargetIPv4FromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetIPv4Key).Return([]byte{88, 200, 23, 9}, true).Once()
	expect := net.IPv4(88, 200, 23, 9)

	ip, err := TargetIPv4FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestTargetIPv4ToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", TargetIPv4Key, []byte{88, 200, 23, 9}).Once()

	err := TargetIPv4ToContainer(c, net.IPv4(88, 200, 23, 9))
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPv6FromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", ClientIPv6Key).Return([]byte(net.IPv6loopback), true).Once()
	expect := net.IPv6loopback

	ip, err := ClientIPv6FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPv6ToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", ClientIPv6Key, []byte(net.IPv6loopback)).Once()

	err := ClientIPv6ToContainer(c, net.IPv6loopback)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestTargetIPv6FromContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetIPv6Key).Return([]byte(net.IPv6loopback), true).Once()
	expect := net.IPv6loopback

	ip, err := TargetIPv6FromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestTargetIPv6ToContainer(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("SetBytes", TargetIPv6Key, []byte(net.IPv6loopback)).Once()

	err := TargetIPv6ToContainer(c, net.IPv6loopback)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv4(t *testing.T) {
	c := tlv.NewContainerMock()
	expect := net.IPv4(88, 200, 23, 9).To4()
	c.On("GetBytes", ClientIPv4Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv6(t *testing.T) {
	c := tlv.NewContainerMock()
	expect := net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")
	c.On("GetBytes", ClientIPv6Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_IPv4AndIPv6(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte(net.IPv4(88, 200, 23, 9).To4()), true).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte(net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")), true).Once()

	ip, err := ClientIPFromContainer(c)
	assert.ErrorIs(t, err, ErrViolationOfProtocolSpec)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestClientIPFromContainer_Empty(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", ClientIPv4Key).Return([]byte{}, false).Once()
	c.On("GetBytes", ClientIPv6Key).Return([]byte{}, false).Once()

	ip, err := ClientIPFromContainer(c)
	assert.ErrorIs(t, err, ErrMissingEntry)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestTargetIPFromContainer_IPv4(t *testing.T) {
	c := tlv.NewContainerMock()
	expect := net.IPv4(88, 200, 23, 9).To4()
	c.On("GetBytes", TargetIPv4Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", TargetIPv6Key).Return([]byte{}, false).Once()

	ip, err := TargetIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestTargetIPFromContainer_IPv6(t *testing.T) {
	c := tlv.NewContainerMock()
	expect := net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")
	c.On("GetBytes", TargetIPv6Key).Return([]byte(expect), true).Once()
	c.On("GetBytes", TargetIPv4Key).Return([]byte{}, false).Once()

	ip, err := TargetIPFromContainer(c)
	assert.NoError(t, err)
	assert.True(t, expect.Equal(ip))

	c.AssertExpectations(t)
}

func TestTargetIPFromContainer_IPv4AndIPv6(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetIPv4Key).Return([]byte(net.IPv4(88, 200, 23, 9).To4()), true).Once()
	c.On("GetBytes", TargetIPv6Key).Return([]byte(net.ParseIP("2001:1470:fffd:2073:250:56ff:fe81:741f")), true).Once()

	ip, err := TargetIPFromContainer(c)
	assert.ErrorIs(t, err, ErrViolationOfProtocolSpec)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestTargetIPFromContainer_Empty(t *testing.T) {
	c := tlv.NewContainerMock()
	c.On("GetBytes", TargetIPv4Key).Return([]byte{}, false).Once()
	c.On("GetBytes", TargetIPv6Key).Return([]byte{}, false).Once()

	ip, err := TargetIPFromContainer(c)
	assert.ErrorIs(t, err, ErrMissingEntry)
	assert.Nil(t, ip)

	c.AssertExpectations(t)
}

func TestNonceFromContainer(t *testing.T) {
	b := make([]byte, 3)
	rand.Read(b)

	c := tlv.NewContainerMock()
	c.On("GetBytes", NonceKey).Return(b, true).Once()

	n, err := NonceFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, b, n)

	c.AssertExpectations(t)
}

func TestNonceToContainer(t *testing.T) {
	b := make([]byte, 3)
	rand.Read(b)

	c := tlv.NewContainerMock()
	c.On("SetBytes", NonceKey, b).Once()

	err := NonceToContainer(c, b)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestDurationFromContainer(t *testing.T) {
	b, err := DurationEncode(time.Hour)
	assert.NoError(t, err)

	c := tlv.NewContainerMock()
	c.On("GetBytes", DurationKey).Return(b, true).Once()

	d, err := DurationFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, time.Hour, d)

	c.AssertExpectations(t)
}

func TestDurationToContainer(t *testing.T) {
	d := time.Hour
	b, err := DurationEncode(d)
	assert.NoError(t, err)

	c := tlv.NewContainerMock()
	c.On("SetBytes", DurationKey, b).Once()

	err = DurationToContainer(c, d)
	assert.NoError(t, err)

	c.AssertExpectations(t)
}

func TestClientUUIDFromContainer(t *testing.T) {
	u := uuid.NewV4()
	b := u.Bytes()

	c := tlv.NewContainerMock()
	c.On("GetBytes", ClientUUIDKey).Return(b, true).Once()

	id, err := ClientUUIDFromContainer(c)
	assert.NoError(t, err)
	assert.Equal(t, u.String(), id)

	c.AssertExpectations(t)
}

func TestClientUUIDToContainer(t *testing.T) {
	u := uuid.NewV4()

	c := tlv.NewContainerMock()
	c.On("SetBytes", ClientUUIDKey, u.Bytes()).Once()

	err := ClientUUIDToContainer(c, u.String())
	assert.NoError(t, err)

	c.AssertExpectations(t)
}
