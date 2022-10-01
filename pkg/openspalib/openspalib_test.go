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
	clientUUID := RandomUUID()

	// Client: Create request
	r, err := NewRequest(RequestData{
		TransactionID:   42,
		ClientUUID:      clientUUID,
		ClientIP:        net.IPv4(88, 200, 23, 30),
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        net.IPv4(88, 200, 23, 40),
		TargetPortStart: 80,
		TargetPortEnd:   100,
	}, cs, RequestDataOpt{})
	require.NoError(t, err)
	reqBytes, err := r.Marshal()
	require.NoError(t, err)

	// Server: Receive request
	rS, err := RequestUnmarshal(reqBytes, cs)
	require.NotNil(t, rS)
	assert.Equal(t, 2, rS.Header.Version)
	assert.Equal(t, uint8(42), rS.Header.TransactionID)
	require.NoError(t, err)

	firewallC, err := TLVFromContainer(rS.Body, FirewallKey)
	assert.NoError(t, err)
	assert.NotNil(t, firewallC)

	proto, err := TargetProtocolFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, proto)

	portA, err := TargetPortStartFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, 80, portA)

	portB, err := TargetPortEndFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, 100, portB)

	cIP, err := ClientIPFromContainer(firewallC)
	assert.NoError(t, err)
	assert.True(t, net.IPv4(88, 200, 23, 30).Equal(cIP))

	sIP, err := TargetIPFromContainer(firewallC)
	assert.NoError(t, err)
	assert.True(t, net.IPv4(88, 200, 23, 40).Equal(sIP))

	// Server: Send response
	resp, err := NewResponse(ResponseData{
		TransactionID:   42,
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        net.IPv4(88, 200, 23, 8),
		TargetPortStart: 80,
		TargetPortEnd:   100,
		Duration:        3 * time.Second,
		ClientUUID:      clientUUID,
	}, cs)
	require.NoError(t, err)
	require.NotNil(t, resp)
	respBytes, err := resp.Marshal()
	assert.NoError(t, err)

	// Client: Receive response
	respC, err := ResponseUnmarshal(respBytes, cs)
	assert.NoError(t, err)
	require.NotNil(t, respC)
	assert.Equal(t, 2, respC.Header.Version)
	assert.Equal(t, uint8(42), respC.Header.TransactionID)

	firewallS, err := TLVFromContainer(respC.Body, FirewallKey)
	assert.NoError(t, err)
	assert.NotNil(t, firewallS)

	proto, err = TargetProtocolFromContainer(firewallS)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, proto)

	tIP, err := TargetIPFromContainer(firewallS)
	assert.NoError(t, err)
	assert.True(t, net.IPv4(88, 200, 23, 8).Equal(tIP))

	portA, err = TargetPortStartFromContainer(firewallS)
	assert.NoError(t, err)
	assert.Equal(t, 80, portA)

	portB, err = TargetPortEndFromContainer(firewallS)
	assert.NoError(t, err)
	assert.Equal(t, 100, portB)

	d, err := DurationFromContainer(firewallS)
	assert.NoError(t, err)
	assert.Equal(t, 3*time.Second, d)
}
