package openspalib

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

	cid, err := ClientUUIDFromContainer(r.Body)
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

func TestRequestSize_Stub(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	r, err := NewRequest(testRequestData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=None test Request marshaled size: %d", len(b))
}

func TestRequestSize_rsa2048_sha256_aes_256_cbc(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	pub2, ok := key2.Public().(*rsa.PublicKey)
	assert.True(t, ok)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA2048_SHA256_AES256CBC(key1, res)

	r, err := NewRequest(testRequestData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=RSA2048_SHA256_AES_256_CBC test Request marshaled size: %d", len(b))
}

func testRequestData() RequestData {
	return RequestData{
		TransactionId: 123,
		ClientUUID:    RandomUUID(),
		Protocol:      ProtocolIPV4,
		PortStart:     80,
		PortEnd:       120,
		ClientIP:      net.IPv4(88, 200, 23, 100),
		ServerIP:      net.IPv4(88, 200, 23, 200),
	}
}
