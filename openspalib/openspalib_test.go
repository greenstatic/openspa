package openspalib

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSpaLib_EndToEnd(t *testing.T) {
	cs := NewCipherSuiteMock()
	cs.On("CipherSuiteId").Return(0)
	//cs.On("Secure")

	// Client: Create request
	r, err := NewRequest(RequestData{}, cs)
	require.NoError(t, err)
	reqBytes, err := r.Marshal()
	require.NoError(t, err)

	// Server: Receive request
	rS, err := RequestUnmarshal(reqBytes)
	require.NotNil(t, rS)
	assert.Equal(t, 1, rS.Header.Version)
	require.NoError(t, err)

	portA, err := FirewallPortStartFromContainer(rS.Body)
	assert.NoError(t, err)
	portB, err := FirewallPortEndFromContainer(rS.Body)
	assert.NoError(t, err)
	cIP, err := ClientIPFromContainer(rS.Body)
	assert.NoError(t, err)

	_ = cIP
	_ = portB
	_ = portA

	// Server: Send response
	resp, err := NewResponse(ResponseData{
		// TODO
	})
	require.NotNil(t, resp)
	require.NoError(t, err)
	respBytes, err := resp.Marshal()
	assert.NoError(t, err)

	// Client: Receive response
	respC, err := ResponseUnmarshal(respBytes)
	assert.NoError(t, err)

	d, err := DurationFromContainer(respC.Body)
	assert.NoError(t, err)

	_ = d
}
