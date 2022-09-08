package openspalib

import (
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
		TransactionID:   123,
		ClientUUID:      clientUUID,
		TargetProtocol:  ProtocolIPV4,
		TargetPortStart: 80,
		TargetPortEnd:   120,
		ClientIP:        clientIP,
		TargetIP:        serverIP,
	}, cs)

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionID)

	tstamp, err := TimestampFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Greater(t, float64(1), time.Since(tstamp).Seconds())

	cid, err := ClientUUIDFromContainer(r.Body)
	assert.NoError(t, err)
	assert.Equal(t, clientUUID, cid)

	firewall, err := TLVFromContainer(r.Body, FirewallKey)
	assert.NoError(t, err)
	assert.NotNil(t, firewall)

	p, err := TargetProtocolFromContainer(firewall)
	assert.NoError(t, err)
	assert.Equal(t, ProtocolIPV4, p)

	ps, err := TargetPortStartFromContainer(firewall)
	assert.NoError(t, err)
	assert.Equal(t, 80, ps)

	pe, err := TargetPortEndFromContainer(firewall)
	assert.NoError(t, err)
	assert.Equal(t, 120, pe)

	cip, err := ClientIPFromContainer(firewall)
	assert.NoError(t, err)
	assert.True(t, clientIP.Equal(cip))

	sip, err := TargetIPFromContainer(firewall)
	assert.NoError(t, err)
	assert.True(t, serverIP.Equal(sip))

	b, err := r.Marshal()
	assert.NoError(t, err)

	// Multiple unmarshals should be ok
	r2, err := RequestUnmarshal(b, cs)
	assert.NoError(t, err)
	r3, err := RequestUnmarshal(b, cs)
	assert.NoError(t, err)

	assert.Equal(t, r.Header.TransactionID, r2.Header.TransactionID)
	assert.Equal(t, r.Header.TransactionID, r3.Header.TransactionID)
}

func TestRequestUnmarshal(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	b, err := h.Marshal()
	assert.NoError(t, err)

	r, err := RequestUnmarshal(b, crypto.NewCipherSuiteStub())
	assert.Error(t, err)
	assert.Nil(t, r)
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

func TestRequestSize_RSA_SHA256_AES_256_CBC_with2048Keypair(t *testing.T) {
	key1, _, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(2048)
	assert.NoError(t, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything, nil).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res)

	r, err := NewRequest(testRequestData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=RSA_SHA256_AES_256_CBC (2048 client and server keypair) test Request marshaled size: %d", len(b))
}

func TestRequestSize_RSA_SHA256_AES_256_CBC_with4096Keypair(t *testing.T) {
	key1, _, err := crypto.RSAKeypair(4096)
	assert.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(4096)
	assert.NoError(t, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything, nil).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res)

	r, err := NewRequest(testRequestData(), cs)
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.Less(t, 0, len(b))
	assert.NoError(t, err)

	t.Logf("Cipher=RSA_SHA256_AES_256_CBC (4096 client and server keypair) test Request marshaled size: %d", len(b))
}

func testRequestData() RequestData {
	return RequestData{
		TransactionID:   123,
		ClientUUID:      RandomUUID(),
		TargetProtocol:  ProtocolIPV4,
		TargetPortStart: 80,
		TargetPortEnd:   120,
		ClientIP:        net.IPv4(88, 200, 23, 100),
		TargetIP:        net.IPv4(88, 200, 23, 200),
	}
}

func TestRequestDataToContainer_And_RequestFirewallDataFromContainer(t *testing.T) {
	rd := RequestData{
		TransactionID:   123,
		ClientUUID:      "87d809fb-7aea-46db-94f8-1d9275bd61ce",
		ClientIP:        net.IPv4(88, 200, 23, 100),
		TargetProtocol:  ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 200),
		TargetPortStart: 80,
		TargetPortEnd:   443,
	}

	red := RequestExtendedData{
		Timestamp: time.Now().UTC(),
	}

	c, err := RequestDataToContainer(rd, red)
	assert.NoError(t, err)

	fwd, err := RequestFirewallDataFromContainer(c)
	assert.NoError(t, err)

	assert.WithinDuration(t, red.Timestamp, fwd.Timestamp, time.Second)
	assert.Equal(t, rd.ClientUUID, fwd.ClientUUID)
	assert.True(t, rd.ClientIP.Equal(fwd.ClientIP))
	assert.True(t, rd.TargetIP.Equal(fwd.TargetIP))
	assert.Equal(t, rd.TargetProtocol, fwd.TargetProtocol)
	assert.Equal(t, rd.TargetPortStart, fwd.TargetPortStart)
	assert.Equal(t, rd.TargetPortEnd, fwd.TargetPortEnd)

}
