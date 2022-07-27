package crypto

import (
	"crypto"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/stretchr/testify/mock"
)

var _ CipherSuite = &CipherSuiteMock{}

type CipherSuiteMock struct {
	mock.Mock
}

func NewCipherSuiteMock() *CipherSuiteMock {
	c := &CipherSuiteMock{}
	return c
}

func (c *CipherSuiteMock) CipherSuiteId() CipherSuiteId {
	args := c.Called()
	return CipherSuiteId(uint8(args.Int(0)))
}

func (c *CipherSuiteMock) Secure(header []byte, body tlv.Container) (tlv.Container, error) {
	args := c.Called(header, body)
	return args.Get(0).(tlv.Container), args.Error(1)
}

func (c *CipherSuiteMock) Unlock(header []byte, ec tlv.Container) (tlv.Container, error) {
	args := c.Called(header, ec)
	return args.Get(0).(tlv.Container), args.Error(1)
}

func (c *CipherSuiteMock) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	args := c.Called(plaintext)
	return args.Get(0).([]byte), args.Error(1)
}

func (c *CipherSuiteMock) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	args := c.Called(ciphertext)
	return args.Get(0).([]byte), args.Error(1)
}

func (c *CipherSuiteMock) Sign(data []byte) (signature []byte, err error) {
	args := c.Called(data)
	return args.Get(0).([]byte), args.Error(1)
}

func (c *CipherSuiteMock) Verify(text, signature []byte) (valid bool, err error) {
	args := c.Called(text, signature)
	return args.Bool(0), args.Error(1)
}

var _ CipherSuite = &CipherSuiteStub{}

type CipherSuiteStub struct{}

func NewCipherSuiteStub() *CipherSuiteStub {
	c := &CipherSuiteStub{}
	return c
}

func (c *CipherSuiteStub) CipherSuiteId() CipherSuiteId {
	return CipherNoSecurity
}

func (c *CipherSuiteStub) Secure(header []byte, body tlv.Container) (tlv.Container, error) {
	return body, nil
}

func (c *CipherSuiteStub) Unlock(header []byte, ec tlv.Container) (tlv.Container, error) {
	return ec, nil
}

var _ PublicKeyLookuper = &PublicKeyLookupMock{}

type PublicKeyLookupMock struct {
	mock.Mock
}

func NewPublicKeyLookupMock() *PublicKeyLookupMock {
	p := &PublicKeyLookupMock{}
	return p
}

func (p *PublicKeyLookupMock) LookupPublicKey(clientId string) (crypto.PublicKey, error) {
	args := p.Called(clientId)
	return args.Get(0).(crypto.PublicKey), args.Error(1)
}

var _ PublicKeyResolver = &PublicKeyResolverMock{}

type PublicKeyResolverMock struct {
	mock.Mock
}

func NewPublicKeyResolverMock() *PublicKeyResolverMock {
	p := &PublicKeyResolverMock{}
	return p
}

func (p *PublicKeyResolverMock) PublicKey(packet tlv.Container) (crypto.PublicKey, error) {
	args := p.Called(packet)
	return args.Get(0).(crypto.PublicKey), args.Error(1)
}
