package openspalib

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
)

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

type TLVType uint16

const (
	TypeEncryptedData TLVType = 0x01
	TypeTimestamp TLVType = 0x02
	TypeClientDeviceUUID TLVType = 0x03
	TypeFirewallProtocol TLVType = 0x04
	TypeFirewallPortStart TLVType = 0x05
	TypeFirewallPortEnd TLVType = 0x06
	TypeClientPublicIPv6 TLVType = 0x07
	TypeServerPublicIPv6 TLVType = 0x08
	TypeClientPublicIPv4 TLVType = 0x09
	TypeServerPublicIPv4 TLVType = 0x0A
	TypeClientBehindNAT TLVType = 0x0B
	TypeSignature TLVType = 0x0C
	TypeNonce TLVType = 0x0D
	TypeDuration TLVType = 0x0E
	TypeClientUsername TLVType = 0x0F
)

func (t TLVType) Byte() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(t))
	return b
}

// Hex returns the type as a hexadecimal encoded string without the 0x prefix. The letters A-F will be upper-case.
func (t TLVType) Hex() string {
	b := t.Byte()
	return strings.ToUpper(hex.EncodeToString(b))
}
