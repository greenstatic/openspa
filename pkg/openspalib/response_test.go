package openspalib

import (
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNewResponse(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	dur := 3 * time.Hour

	r, err := NewResponse(ResponseData{
		TransactionId: 123,
		Protocol:      ProtocolIPV4,
		PortStart:     80,
		PortEnd:       120,
		Duration:      dur,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionId)

	p, err := ProtocolFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, p)

	ps, err := PortStartFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, 80, ps)

	pe, err := PortEndFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, 120, pe)

	d, err := DurationFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, dur, d)

	non, err := NonceFromContainer(r.Body)
	assert.NoError(t, err)
	assert.NotNil(t, non)
	assert.NotEqual(t, []byte{0, 0, 0}, non)
	assert.Len(t, non, NonceSize)
}
