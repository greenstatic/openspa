package openspalib

import (
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestHeader_MarshalRequestType(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	b, err := h.Marshal()

	assert.NoError(t, err)
	assert.Len(t, b, 8)
	assert.Equal(t, []byte{
		0x10, // Control field: type: request, version: 1
		0x00, // Transaction ID: 0
		0xff, // Cipher Suite: No Security
		0x00, // reserved field
		0x00, // ADK0
		0x00, // ADK1
		0x00, // ADK2
		0x00, // ADK3
	}, b)
}

func TestHeader_MarshalResponseTypeCipher24(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherSuiteID(24))
	b, err := h.Marshal()

	assert.NoError(t, err)
	assert.Len(t, b, 8)
	assert.Equal(t, []byte{
		0x90, // Control field: type: response, version: 1
		0x00, // Transaction ID: 0
		0x18, // Cipher Suite: 24
		0x00, // reserved field
		0x00, // ADK0
		0x00, // ADK1
		0x00, // ADK2
		0x00, // ADK3
	}, b)
}

func TestHeader_MarshalRequestTransaction123(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	h.TransactionID = 123
	b, err := h.Marshal()

	assert.NoError(t, err)
	assert.Len(t, b, 8)
	assert.Equal(t, []byte{
		0x10, // Control field: type: request, version: 1
		0x7B, // Transaction ID: 123
		0xff, // Cipher Suite: No Security
		0x00, // reserved field
		0x00, // ADK0
		0x00, // ADK1
		0x00, // ADK2
		0x00, // ADK3
	}, b)
}

func TestHeader_MarshalRequestVersion2(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	h.Version = 2
	b, err := h.Marshal()

	assert.NoError(t, err)
	assert.Len(t, b, 8)
	assert.Equal(t, []byte{
		0x20, // Control field: type: request, version: 2
		0x00, // Transaction ID: 00
		0xff, // Cipher Suite: No Security
		0x00, // reserved field
		0x00, // ADK0
		0x00, // ADK1
		0x00, // ADK2
		0x00, // ADK3
	}, b)
}

func TestHeaderMarshalControlField_RequestVersion1(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	h.Version = 1
	b := h.marshalControlField()

	assert.Equal(t, byte(0x10), b)
}

func TestHeaderMarshalControlField_RequestVersion2(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherNoSecurity)
	h.Version = 2
	b := h.marshalControlField()

	assert.Equal(t, byte(0x20), b)
}

func TestHeaderMarshalControlField_ResponseVersion1(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	b := h.marshalControlField()

	assert.Equal(t, byte(0x90), b)
}

func TestHeaderMarshalTransactionId_0(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	b := h.marshalTransactionID()

	assert.Equal(t, byte(0x00), b)
}

func TestHeaderMarshalTransactionId_1(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	h.TransactionID = 1
	b := h.marshalTransactionID()

	assert.Equal(t, byte(0x01), b)
}

func TestHeaderMarshalTransactionId_123(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	h.TransactionID = 123
	b := h.marshalTransactionID()

	assert.Equal(t, byte(0x7B), b)
}

func TestHeaderMarshalTransactionId_255(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	h.TransactionID = 255
	b := h.marshalTransactionID()

	assert.Equal(t, byte(0xFF), b)
}

func TestHeaderMarshalCipherSuite_NoSecurity(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherNoSecurity)
	b := h.marshalCipherSuite()

	assert.Equal(t, byte(0xff), b)
}

func TestHeaderMarshalCipherSuite_123(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherSuiteID(123))
	b := h.marshalCipherSuite()

	assert.Equal(t, byte(0x7B), b)
}

func TestHeaderMarshalCipherSuite_255(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherSuiteID(255))
	b := h.marshalCipherSuite()

	assert.Equal(t, byte(0xFF), b)
}

func TestHeaderMarshalADK_Length(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherSuiteID(255))
	b := h.marshalADK()

	assert.Len(t, b, 4)
}

func TestHeaderUnmarshalControlField(t *testing.T) {
	h := Header{}

	ty, v := h.unmarshalControlField(0x90)
	assert.Equal(t, 1, v)
	assert.Equal(t, ResponsePDU, ty)

	ty, v = h.unmarshalControlField(0x9F)
	assert.Equal(t, 1, v)
	assert.Equal(t, ResponsePDU, ty)

	ty, v = h.unmarshalControlField(0x10)
	assert.Equal(t, 1, v)
	assert.Equal(t, RequestPDU, ty)

	ty, v = h.unmarshalControlField(0x1F)
	assert.Equal(t, 1, v)
	assert.Equal(t, RequestPDU, ty)
}

func TestUnmarshalHeader_RequestPDU(t *testing.T) {
	h := NewHeader(RequestPDU, crypto.CipherRSA_SHA256_AES256CBC_ID)
	h.Version = 2
	h.TransactionID = 123
	b, err := h.Marshal()
	assert.NoError(t, err)

	header, err := UnmarshalHeader(b)
	assert.NoError(t, err)

	assert.Equal(t, RequestPDU, header.Type)
	assert.Equal(t, uint8(123), header.TransactionID)
	assert.Equal(t, crypto.CipherRSA_SHA256_AES256CBC_ID, header.CipherSuiteID)
	assert.Equal(t, 2, header.Version)
}

func TestUnmarshalHeader_ResponsePDU(t *testing.T) {
	h := NewHeader(ResponsePDU, crypto.CipherRSA_SHA256_AES256CBC_ID)
	h.TransactionID = 123
	b, err := h.Marshal()
	assert.NoError(t, err)

	header, err := UnmarshalHeader(b)
	assert.NoError(t, err)

	assert.Equal(t, ResponsePDU, header.Type)
	assert.Equal(t, uint8(123), header.TransactionID)
	assert.Equal(t, crypto.CipherRSA_SHA256_AES256CBC_ID, header.CipherSuiteID)
	assert.Equal(t, 1, header.Version)
}
