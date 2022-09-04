package openspalib

import (
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewResponse(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()
	clientUUID := RandomUUID()
	dur := 3 * time.Hour

	tIP := net.IPv4(88, 200, 23, 19)
	r, err := NewResponse(ResponseData{
		TransactionID:   123,
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        tIP,
		TargetPortStart: 80,
		TargetPortEnd:   120,
		Duration:        dur,
		ClientUUID:      clientUUID,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionID)

	firewallC, err := TLVFromContainer(r.Body, FirewallKey)
	assert.NoError(t, err)
	assert.NotNil(t, firewallC)
	assert.NotEqual(t, 0, firewallC.NoEntries())

	p, err := TargetProtocolFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, p)

	ip, err := TargetIPFromContainer(firewallC)
	assert.NoError(t, err)
	assert.True(t, tIP.Equal(ip))

	ps, err := TargetPortStartFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, 80, ps)

	pe, err := TargetPortEndFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, 120, pe)

	d, err := DurationFromContainer(firewallC)
	assert.NoError(t, err)
	assert.Equal(t, dur, d)

	uuid, err := ClientUUIDFromContainer(r.Metadata)
	assert.NoError(t, err)
	assert.Equal(t, clientUUID, uuid)
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

func TestResponse_bodyCreate(t *testing.T) {
	c := tlv.NewContainer()
	r := Response{}
	rd := ResponseData{
		TransactionID:   RandomTransactionID(),
		ClientUUID:      RandomUUID(),
		TargetProtocol:  ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 24),
		TargetPortStart: 80,
		TargetPortEnd:   2000,
		Duration:        time.Hour,
	}

	ed, err := r.generateExtendedData()
	assert.NoError(t, err)
	assert.NoError(t, r.bodyCreate(c, rd, ed))

	firewallC, err := TLVFromContainer(c, FirewallKey)
	assert.NoError(t, err)
	assert.NotNil(t, firewallC)

	_, err = TargetProtocolFromContainer(firewallC)
	assert.NoError(t, err)

	_, err = TargetIPFromContainer(firewallC)
	assert.NoError(t, err)

	_, err = TargetPortStartFromContainer(firewallC)
	assert.NoError(t, err)

	_, err = TargetPortEndFromContainer(firewallC)
	assert.NoError(t, err)

	_, err = DurationFromContainer(firewallC)
	assert.NoError(t, err)
}

func TestResponse_metadataCreate(t *testing.T) {
	c := tlv.NewContainer()
	r := Response{}
	rd := ResponseData{
		TransactionID:   RandomTransactionID(),
		ClientUUID:      RandomUUID(),
		TargetProtocol:  ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 24),
		TargetPortStart: 80,
		TargetPortEnd:   2000,
		Duration:        time.Hour,
	}
	assert.NoError(t, r.metadataCreate(c, rd))

	_, err := ClientUUIDFromContainer(c)
	assert.NoError(t, err)
}

func TestResponseSize_RSA_SHA256_AES_256_CBC_with2048Keypair(t *testing.T) {
	key1, _, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything, mock.Anything).Return(pub2, nil)

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
	res.On("PublicKey", mock.Anything, mock.Anything).Return(pub2, nil)

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
		TransactionID:   123,
		TargetProtocol:  ProtocolIPV4,
		TargetIP:        net.ParseIP("2001:1470:fffd:66::23:19"),
		TargetPortStart: 80,
		TargetPortEnd:   100,
		Duration:        time.Hour,
		ClientUUID:      RandomUUID(),
	}
}
