package openspalib

import (
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	clientUUID := RandomUUID()
	clientIP := net.IPv4(88, 200, 23, 100)
	serverIP := net.IPv4(88, 200, 23, 200)

	r, err := NewRequest(RequestData{
		TransactionId: 123,
		ClientUUID:    clientUUID,
		Protocol:      ProtocolIPV4,
		PortStart:     80,
		PortEnd:       120,
		ClientIP:      clientIP,
		ServerIP:      serverIP,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionId)

	tstamp, err := TimestampFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Greater(t, float64(1), time.Now().Sub(tstamp).Seconds())

	cid, err := ClientDeviceUUIDFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, clientUUID, cid)

	p, err := ProtocolFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, p)

	ps, err := PortStartFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, 80, ps)

	pe, err := PortEndFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, 120, pe)

	cip, err := ClientIPFromContainer(r.Body)
	assert.NoError(t, err)
	assert.True(t, clientIP.Equal(cip))

	sip, err := ServerIPFromContainer(r.Body)
	assert.NoError(t, err)
	assert.True(t, serverIP.Equal(sip))

	non, err := NonceFromContainer(r.Body)
	assert.NoError(t, err)
	assert.NotNil(t, non)
	assert.NotEqual(t, []byte{0, 0, 0}, non)
	assert.Len(t, non, NonceSize)
}
