package openspalib

import (
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	cs := crypto.NewCipherSuiteMock()
	cs.On("CipherSuiteId").Return(0)

	r, err := NewRequest(RequestData{
		TransactionId: 123,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionId)
}
