package openspalib

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	errors "github.com/pkg/errors"
)

const (
	HeaderLength    = 8
	ADKLength       = 4
	ProtocolVersion = 2
)

type PDUType string

const (
	RequestPDU  PDUType = "request"
	ResponsePDU PDUType = "response"
)

type Header struct {
	Type          PDUType
	Version       int
	TransactionID uint8
	CipherSuiteID crypto.CipherSuiteID
	ADKProof      uint32
}

func NewHeader(t PDUType, c crypto.CipherSuiteID) Header {
	return Header{
		Type:          t,
		Version:       ProtocolVersion,
		TransactionID: 0,
		CipherSuiteID: c,
	}
}

func (h *Header) Marshal() ([]byte, error) {
	b := make([]byte, HeaderLength-ADKLength, HeaderLength)
	b[0x00] = h.marshalControlField()
	b[0x01] = h.marshalTransactionID()
	b[0x02] = h.marshalCipherSuite()
	b[0x03] = 0 // reserved field

	b = append(b, h.marshalADKProof()...)
	return b, nil
}

func (h *Header) marshalControlField() byte {
	// T | Version | Reserved
	// T = PDU Type (1 bit)
	// Version = Protocol version (3 bits)
	// Reserved = Reserved for future use, should be all 0 (4 bits)

	// higher nibble
	b := uint8(h.Version) << 4

	if h.Type == ResponsePDU {
		b |= 0b1000_0000
	} else {
		// response, make sure bit 7 is 0
		b &= 0b0111_1111
	}

	// lower nibble is reserved

	return b
}

func (h *Header) marshalTransactionID() byte {
	return h.TransactionID
}

func (h *Header) marshalCipherSuite() byte {
	return byte(h.CipherSuiteID)
}

func (h *Header) marshalADKProof() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, h.ADKProof)
	return b
}

func (h *Header) unmarshalControlField(b byte) (t PDUType, version int) {
	t = RequestPDU

	if b>>7&0x01 == 1 {
		t = ResponsePDU
	}

	version = int((b >> 4) & 0x03)
	return
}

func (h *Header) unmarshalTransactionID(b byte) uint8 {
	return b
}

func (h *Header) unmarshalCipherSuite(b byte) crypto.CipherSuiteID {
	return crypto.CipherSuiteID(b)
}

func (h *Header) unmarshalADKProof(b []byte) (uint32, error) {
	if len(b) != ADKLength {
		return 0, errors.New("invalid length")
	}

	return binary.BigEndian.Uint32(b), nil
}

func UnmarshalHeader(b []byte) (Header, error) {
	if len(b) != HeaderLength {
		return Header{}, errors.New("invalid header length")
	}

	h := Header{}
	h.Type, h.Version = h.unmarshalControlField(b[0])
	h.TransactionID = h.unmarshalTransactionID(b[1])
	h.CipherSuiteID = h.unmarshalCipherSuite(b[2])
	// b[3] is reserved field
	proof, err := h.unmarshalADKProof(b[4:HeaderLength])
	if err != nil {
		return Header{}, errors.Wrap(err, "unmarshal adk proof")
	}
	h.ADKProof = proof

	return h, nil
}

func RandomTransactionID() uint8 {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b[0]
}
