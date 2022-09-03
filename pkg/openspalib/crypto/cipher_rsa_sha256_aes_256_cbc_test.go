package crypto

import (
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCipherSuite_RSA_SHA256_AES256CBC(t *testing.T) {
	type csTest struct {
		name          string
		clientPrivate *rsa.PrivateKey
		clientPublic  *rsa.PublicKey
		serverPrivate *rsa.PrivateKey
		serverPublic  *rsa.PublicKey
	}

	tests := make([]csTest, 0)

	key2048_1, pub2048_1, err := RSAKeypair(2048)
	assert.NoError(t, err)

	key2048_2, pub2048_2, err := RSAKeypair(2048)
	assert.NoError(t, err)

	tests = append(tests, csTest{
		name:          "Client & Server RSA 2048 keypair",
		clientPrivate: key2048_1,
		clientPublic:  pub2048_1,
		serverPrivate: key2048_2,
		serverPublic:  pub2048_2,
	})

	key3072_1, pub3072_1, err := RSAKeypair(3072)
	assert.NoError(t, err)

	key3072_2, pub3072_2, err := RSAKeypair(3072)
	assert.NoError(t, err)

	tests = append(tests, csTest{
		name:          "Client & Server RSA 3072 keypair",
		clientPrivate: key3072_1,
		clientPublic:  pub3072_1,
		serverPrivate: key3072_2,
		serverPublic:  pub3072_2,
	})

	tests = append(tests, csTest{
		name:          "Client RSA 2048 & Server RSA 3072 keypair",
		clientPrivate: key2048_1,
		clientPublic:  pub2048_1,
		serverPrivate: key3072_2,
		serverPublic:  pub3072_2,
	})

	tests = append(tests, csTest{
		name:          "Client RSA 3072 & Server RSA 2048 keypair",
		clientPrivate: key3072_1,
		clientPublic:  pub3072_1,
		serverPrivate: key2048_2,
		serverPublic:  pub2048_2,
	})

	key4096_1, pub4096_1, err := RSAKeypair(4096)
	assert.NoError(t, err)

	key4096_2, pub4096_2, err := RSAKeypair(4096)
	assert.NoError(t, err)

	tests = append(tests, csTest{
		name:          "Client & Server RSA 4096 keypair",
		clientPrivate: key4096_1,
		clientPublic:  pub4096_1,
		serverPrivate: key4096_2,
		serverPublic:  pub4096_2,
	})

	for i, test := range tests {
		desc := fmt.Sprintf("test index=%d name=%s", i, test.name)

		header := []byte{4, 8, 15, 16, 23, 42}

		// Packet Container
		pc := tlv.NewContainer()
		pc.SetBytes(2, []byte{1, 2, 3, 4, 5})
		pc.SetBytes(5, []byte{5, 4, 3, 2, 1})

		// Client
		resolverClient := NewPublicKeyResolverMock()
		resolverClient.On("PublicKey", mock.Anything, nil).Return(test.serverPublic, nil).Once()

		csClient := NewCipherSuite_RSA_SHA256_AES256CBC(test.clientPrivate, resolverClient)
		assert.Equalf(t, CipherRSA_SHA256_AES256CBC_ID, csClient.CipherSuiteID(), desc)

		ec, err := csClient.Secure(header, pc, nil)
		assert.NoErrorf(t, err, desc)

		// Server
		resolverServer := NewPublicKeyResolverMock()
		resolverServer.On("PublicKey", mock.Anything, nil).Return(test.clientPublic, nil).Once()

		csServer := NewCipherSuite_RSA_SHA256_AES256CBC(test.serverPrivate, resolverServer)
		pcServer, err := csServer.Unlock(header, ec)
		assert.NoErrorf(t, err, desc)
		require.NotNilf(t, pcServer, desc)
		assert.Equalf(t, pc.Bytes(), pcServer.Bytes(), desc)

		// Final asserts
		assert.Truef(t, resolverClient.AssertExpectations(t), desc)
		assert.True(t, resolverServer.AssertExpectations(t), desc)
	}
}

func TestCipherSuite_RSA_SHA256_AES256CBC_UnlockDoesNotModifyContainer(t *testing.T) {
	clientPriv, clientPub, err := RSAKeypair(2048)
	assert.NoError(t, err)

	serverPriv, serverPub, err := RSAKeypair(2048)
	assert.NoError(t, err)

	header := []byte{4, 8, 15, 16, 23, 42}

	// Packet Container
	pc := tlv.NewContainer()
	pc.SetBytes(2, []byte{1, 2, 3, 4, 5})
	pc.SetBytes(5, []byte{5, 4, 3, 2, 1})

	resolverClient := NewPublicKeyResolverMock()
	resolverClient.On("PublicKey", mock.Anything, nil).Return(serverPub, nil).Once()

	csClient := NewCipherSuite_RSA_SHA256_AES256CBC(clientPriv, resolverClient)
	ec, err := csClient.Secure(header, pc, nil)
	assert.NoError(t, err)
	assert.NotNil(t, ec)

	resolverServer := NewPublicKeyResolverMock()
	resolverServer.On("PublicKey", mock.Anything, nil).Return(clientPub, nil).Twice()

	csServer := NewCipherSuite_RSA_SHA256_AES256CBC(serverPriv, resolverServer)

	ec1 := ec.Bytes()

	pcServer, err := csServer.Unlock(header, ec)
	assert.NoError(t, err)
	assert.NotNil(t, pcServer)

	pcServer, err = csServer.Unlock(header, ec)
	assert.NoError(t, err)
	assert.NotNil(t, pcServer)

	ec2 := ec.Bytes()
	assert.Equal(t, ec1, ec2)
}
