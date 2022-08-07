package openspalib

import (
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewResponse(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	dur := 3 * time.Hour

	tIP := net.IPv4(88, 200, 23, 19)
	r, err := NewResponse(ResponseData{
		TransactionId:   123,
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        tIP,
		TargetPortStart: 80,
		TargetPortEnd:   120,
		Duration:        dur,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionId)

	p, err := TargetProtocolFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, p)

	ip, err := TargetIPFromContainer(r.Body)
	assert.NoError(t, err)
	assert.True(t, tIP.Equal(ip))

	ps, err := TargetPortStartFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, 80, ps)

	pe, err := TargetPortEndFromContainer(r.Body)
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

func TestResponseSize_Stub(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()

	r, err := NewResponse(testResponseData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=none test Response marshaled size: %d", len(b))

}

func TestResponseSize_RSA_SHA256_AES_256_CBC_with2048Keypair(t *testing.T) {
	key1, _, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res)

	r, err := NewResponse(testResponseData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=RSA_SHA256_AES_256_CBC (2048 client and server keypair) test Response marshaled size: %d", len(b))
}

func TestResponseSize_RSA_SHA256_AES_256_CBC_with4096Keypair(t *testing.T) {
	key1, _, err := crypto.RSAKeypair(4096)
	assert.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(4096)
	assert.NoError(t, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res)

	r, err := NewResponse(testResponseData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=RSA_SHA256_AES_256_CBC (4096 client and server keypair) test Response marshaled size: %d", len(b))
}

func testResponseData() ResponseData {
	return ResponseData{
		TransactionId:   123,
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        net.ParseIP("2001:1470:fffd:66::23:19"),
		TargetPortStart: 80,
		TargetPortEnd:   100,
		Duration:        time.Hour,
	}
}
