package openspalib

type PDUType uint8

func (t PDUType) Byte() byte {
	if t != 0x00 {
		return 0x01  // response
	}
	return 0x00  // request
}

func NewPDUType(b byte) PDUType {
	if b == 0x0 {
		return PDURequestType
	}
	return PDUResponseType
}

const (
	PDURequestType PDUType = 0x0
	PDUResponseType PDUType = 0x1
)
