package openspalib

import (
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSpaLib_Usability(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	// Client: Create request
	r, err := NewRequest(RequestData{
		TransactionId: 42,
		ClientUUID:    RandomUUID(),
		Protocol:      ProtocolIPV4,
		PortStart:     80,
		PortEnd:       100,
		ClientIP:      net.IPv4(88, 200, 23, 30),
		ServerIP:      net.IPv4(88, 200, 23, 40),
	}, cs)
	require.NoError(t, err)
	reqBytes, err := r.Marshal()
	require.NoError(t, err)

	// Server: Receive request
	rS, err := RequestUnmarshal(reqBytes, cs)
	require.NotNil(t, rS)
	assert.Equal(t, 1, rS.Header.Version)
	assert.Equal(t, uint8(42), rS.Header.TransactionId)
	require.NoError(t, err)

	proto, err := ProtocolFromContainer(rS.Body)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, proto)

	portA, err := PortStartFromContainer(rS.Body)
	assert.NoError(t, err)
	assert.Equal(t, 80, portA)

	portB, err := PortEndFromContainer(rS.Body)
	assert.NoError(t, err)
	assert.Equal(t, 100, portB)

	cIP, err := ClientIPFromContainer(rS.Body)
	assert.NoError(t, err)
	assert.True(t, net.IPv4(88, 200, 23, 30).Equal(cIP))

	sIP, err := ServerIPFromContainer(rS.Body)
	assert.NoError(t, err)
	assert.True(t, net.IPv4(88, 200, 23, 40).Equal(sIP))

	// Server: Send response
	resp, err := NewResponse(ResponseData{
		TransactionId: 42,
		Protocol:      ProtocolIPV4,
		PortStart:     80,
		PortEnd:       100,
		Duration:      3 * time.Second,
	}, cs)
	require.NoError(t, err)
	require.NotNil(t, resp)
	respBytes, err := resp.Marshal()
	assert.NoError(t, err)

	// Client: Receive response
	respC, err := ResponseUnmarshal(respBytes, cs)
	assert.NoError(t, err)
	require.NotNil(t, respC)
	assert.Equal(t, 1, respC.Header.Version)
	assert.Equal(t, uint8(42), respC.Header.TransactionId)

	proto, err = ProtocolFromContainer(respC.Body)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, proto)

	portA, err = PortStartFromContainer(respC.Body)
	assert.NoError(t, err)
	assert.Equal(t, 80, portA)

	portB, err = PortEndFromContainer(respC.Body)
	assert.NoError(t, err)
	assert.Equal(t, 100, portB)

	d, err := DurationFromContainer(respC.Body)
	assert.NoError(t, err)
	assert.Equal(t, 3*time.Second, d)
}
