package crypto

import (
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCipherSuite_RSA2048_SHA256_AES256CBC(t *testing.T) {
	clientPrivateKey := test2048Key
	clientPublicKey := test2048KeyPub

	serverPrivateKey := test2048Key2
	serverPublicKey := test2048KeyPub2

	header := []byte{4, 8, 15, 16, 23, 42}

	// Packet Container
	pc := tlv.NewContainerStub()
	pc.SetBytes(2, []byte{1, 2, 3, 4, 5})
	pc.SetBytes(5, []byte{5, 4, 3, 2, 1})

	// Client
	resolverClient := NewPublicKeyResolverMock()
	resolverClient.On("PublicKey", mock.Anything).Return(serverPublicKey, nil).Once()

	csClient := NewCipherSuite_RSA2048_SHA256_AES256CBC(clientPrivateKey, resolverClient)
	assert.Equal(t, CipherRSA2048_SHA256_AES256CBC_ID, csClient.CipherSuiteId())

	ec, err := csClient.Secure(header, pc)
	assert.NoError(t, err)

	// Server
	resolverServer := NewPublicKeyResolverMock()
	resolverServer.On("PublicKey", mock.Anything).Return(clientPublicKey, nil).Once()

	csServer := NewCipherSuite_RSA2048_SHA256_AES256CBC(serverPrivateKey, resolverServer)
	pcServer, err := csServer.Unlock(header, ec)
	assert.NoError(t, err)
	require.NotNil(t, pcServer)
	assert.Equal(t, pc.Bytes(), pcServer.Bytes())

	// Final asserts
	resolverClient.AssertExpectations(t)
	resolverServer.AssertExpectations(t)
}
