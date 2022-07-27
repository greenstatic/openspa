package openspalib

import "github.com/greenstatic/openspa/pkg/openspalib/crypto"

const (
	HeaderLength = 8
	ADKLength    = 4
)

type PDUType string

const (
	RequestPDU  PDUType = "request"
	ResponsePDU PDUType = "response"
)

type Header struct {
	Type          PDUType
	Version       int
	TransactionId uint8
	CipherSuiteId crypto.CipherSuiteId
}

func NewHeader(t PDUType, c crypto.CipherSuiteId) Header {
	return Header{
		Type:          t,
		Version:       1,
		TransactionId: 0,
		CipherSuiteId: c,
	}
}

func (h *Header) Marshal() ([]byte, error) {
	b := make([]byte, HeaderLength-ADKLength, HeaderLength)
	b[0x00] = h.marshalControlField()
	b[0x01] = h.marshalTransactionId()
	b[0x02] = h.marshalCipherSuite()
	b[0x03] = 0

	b = append(b, h.marshalADK()...)
	return b, nil
}

func (h *Header) marshalControlField() byte {
	b := uint8(h.Version) << 4

	if h.Type == ResponsePDU {
		b |= 0b1000_0000
	} else {
		// response, make sure bit 7 is 0
		b &= 0b0111_1111
	}

	return b
}

func (h *Header) marshalTransactionId() byte {
	return h.TransactionId
}

func (h *Header) marshalCipherSuite() byte {
	return byte(h.CipherSuiteId)
}

func (h *Header) marshalADK() []byte {
	b := make([]byte, 4)
	b[0] = 0
	b[1] = 0
	b[2] = 0
	b[3] = 0
	return b
}
