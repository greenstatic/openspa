package openspalib

import (
	"crypto/rand"
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
	adkSecret := "7O4ZIRI"

	adkProof, err := ADKGenerateProof(adkSecret)
	assert.NoError(t, err)

	r, err := NewRequest(RequestData{
		TransactionID:   123,
		ClientUUID:      clientUUID,
		TargetProtocol:  ProtocolIPV4,
		TargetPortStart: 80,
		TargetPortEnd:   120,
		ClientIP:        clientIP,
		TargetIP:        serverIP,
	}, cs, RequestDataOpt{
		ADKSecret: adkSecret,
	})

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionID)
	assert.Equal(t, adkProof, r.Header.ADKProof)

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
	assert.Equal(t, r.Header.ADKProof, r2.Header.ADKProof)
	assert.Equal(t, r.Header.ADKProof, r3.Header.ADKProof)
}

func TestNewRequest_WithNoADKProof(t *testing.T) {
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
	}, cs, RequestDataOpt{
		ADKSecret: "",
	})

	assert.NoError(t, err)
	assert.NotNil(t, r)

	assert.Equal(t, byte(123), r.Header.TransactionID)
	assert.Equal(t, uint32(0), r.Header.ADKProof)

	b, err := r.Marshal()
	assert.NoError(t, err)

	// Multiple unmarshals should be ok
	r2, err := RequestUnmarshal(b, cs)
	assert.NoError(t, err)
	r3, err := RequestUnmarshal(b, cs)
	assert.NoError(t, err)

	assert.Equal(t, r.Header.TransactionID, r2.Header.TransactionID)
	assert.Equal(t, r.Header.TransactionID, r3.Header.TransactionID)
	assert.Equal(t, uint32(0), r2.Header.ADKProof)
	assert.Equal(t, uint32(0), r3.Header.ADKProof)
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

	r, err := NewRequest(testRequestData(), cs, RequestDataOpt{})
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

	r, err := NewRequest(testRequestData(), cs, RequestDataOpt{})
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

	r, err := NewRequest(testRequestData(), cs, RequestDataOpt{})
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

func TestRequestUnmarshalHeader(t *testing.T) {
	cs := crypto.NewCipherSuiteStub()
	r, err := NewRequest(testRequestData(), cs, RequestDataOpt{})
	assert.NoError(t, err)
	assert.NotNil(t, r)

	b, err := r.Marshal()
	assert.NoError(t, err)

	_, err = RequestUnmarshalHeader(b)
	assert.NoError(t, err)

	// These should fail
	_, err = RequestUnmarshalHeader(nil)
	assert.Error(t, err)
	_, err = RequestUnmarshalHeader([]byte{})
	assert.Error(t, err)
	_, err = RequestUnmarshalHeader([]byte{0x1})
	assert.Error(t, err)
	_, err = RequestUnmarshalHeader([]byte{0x1, 0x00, 0x00, 0x00})
	assert.Error(t, err)
}

func BenchmarkRequestUnmarshal_RSA_SHA256_AES_256_CBC_with2048Keypair(b *testing.B) {
	key1, pub1, err := crypto.RSAKeypair(2048)
	assert.NoError(b, err)

	key2, pub2, err := crypto.RSAKeypair(2048)
	assert.NoError(b, err)

	res1 := crypto.NewPublicKeyResolverMock()
	res1.On("PublicKey", mock.Anything, nil).Return(pub2, nil)
	cs1 := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res1)

	res2 := crypto.NewPublicKeyResolverMock()
	res2.On("PublicKey", mock.Anything, mock.Anything).Return(pub1, nil)
	cs2 := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key2, res2)

	r, err := NewRequest(testRequestData(), cs1, RequestDataOpt{})
	assert.NoError(b, err)
	assert.NotNil(b, r)

	buff, err := r.Marshal()
	assert.NoError(b, err)

	buff[len(buff)-1] ^= 0xFE // taint the encrypted session last byte to make decryption fail

	b.Logf("request unmarshal buff size: %d", len(buff))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = RequestUnmarshal(buff, cs2)
		assert.Error(b, err)
	}
}

func BenchmarkRequestUnmarshal_RSA_SHA256_AES_256_CBC_with2048Keypair_withFakeData(b *testing.B) {
	const buffSize = 50
	const overhead = 8 + 4 + 2 // header + encrypted payload tlv entry + encrypted session tlv type and length
	const encryptedSessionSize = buffSize - overhead
	assert.Equal(b, encryptedSessionSize, 36)

	buff := []byte{
		0x20, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // Header
		0x01, 0x02, 0x42, 0x24, // Encrypted Payload TLV entry
		0x02, encryptedSessionSize, // Encrypted session (decrypt using RSA) TLV entry
	}

	for i := 0; i < encryptedSessionSize; i++ {
		byt := []byte{0x00}
		_, err := rand.Read(byt)
		assert.NoError(b, err)
		buff = append(buff, byt[0])
	}

	assert.Len(b, buff, buffSize)

	key1, _, err := crypto.RSAKeypair(2048)
	assert.NoError(b, err)

	_, pub2, err := crypto.RSAKeypair(2048)
	assert.NoError(b, err)

	res := crypto.NewPublicKeyResolverMock()
	res.On("PublicKey", mock.Anything, nil).Return(pub2, nil)

	cs := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(key1, res)

	b.Logf("request unmarshal buff size: %d", len(buff))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = RequestUnmarshal(buff, cs)
		assert.Error(b, err)
	}
}
