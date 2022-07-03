package openspalib_old

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

type PDUType uint8

func (t PDUType) Byte() byte {
	if t != 0x00 {
		return 0x01 // response
	}
	return 0x00 // request
}

func NewPDUType(b byte) PDUType {
	if b == 0x0 {
		return PDURequestType
	}
	return PDUResponseType
}

const (
	PDURequestType  PDUType = 0x0
	PDUResponseType PDUType = 0x1
)

type TLVType uint16

const (
	// TypeEncryptedContainer contains as data another TLV21 container that is encrypted
	TypeEncryptedContainer TLVType = 0x01 // Format: bytes     			Length: variable bytes
	// TypeContainer contains as data another TLV21 container (unencrypted)
	TypeContainer         TLVType = 0x02 // Format: bytes     			Length: variable bytes
	TypeSignature         TLVType = 0x03 // Format: bytes     			Length: variable bytes
	TypeTimestamp         TLVType = 0x04 // Format: integer   			Length: 8 bytes
	TypeClientDeviceUUID  TLVType = 0x05 // Format: unsigned integer	Length: 16 bytes
	TypeFirewallProtocol  TLVType = 0x06 // Format: unsigned integer   Length: 1 byte
	TypeFirewallPortStart TLVType = 0x07 // Format: unsigned integer 	Length: 2 bytes
	TypeFirewallPortEnd   TLVType = 0x08 // Format: unsigned integer   Length: 2 bytes
	TypeClientPublicIPv6  TLVType = 0x09 // Format: unsigned integer   Length: 16 bytes
	TypeServerPublicIPv6  TLVType = 0x0A // Format: unsigned integer   Length: 16 bytes
	TypeClientPublicIPv4  TLVType = 0x0B // Format: unsigned integer   Length: 4 bytes
	TypeServerPublicIPv4  TLVType = 0x0C // Format: unsigned integer   Length: 4 bytes
	TypeIPInfo            TLVType = 0x0D // Format: unsigned integer   Length: 1 byte
	TypeNonce             TLVType = 0x0E // Format: unsigned integer   Length: variable bytes
	TypeDuration          TLVType = 0x0F // Format: unsigned integer   Length: variable bytes
	//TypeClientIdentifier TLVType = 0x10   // Format: UTF-8     Length: variable bytes
)

func (t TLVType) Byte() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(t))
	return b
}

func (t TLVType) Uint16() uint16 {
	return uint16(t)
}

// Hex returns the type as a hexadecimal encoded string without the 0x prefix. The letters A-F will be upper-case.
func (t TLVType) Hex() string {
	b := t.Byte()
	return strings.ToUpper(hex.EncodeToString(b))
}

type IPInfo struct {
	ClientBehindNAT bool
}

func (i IPInfo) Encode() byte {
	return ipInfoEncode(i)
}

// Encodes a time.Time field into a unix 64-bit timestamp - 8 byte slice
func timestampEncode(timestamp time.Time) []byte {
	b := make([]byte, 8)
	i := timestamp.Unix()
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// Decodes an 8-byte timestamp byte slice into a time.Time field
func timestampDecode(data []byte) (time.Time, error) {
	const timestampSize = 8 // bytes

	if len(data) != timestampSize {
		return time.Time{}, ErrInvalidBytes
	}

	i := binary.BigEndian.Uint64(data)
	t := time.Unix(int64(i), 0)

	return t, nil
}

// Encodes the client's device UUID v4 identifier. The function removes the dashes and returns a byte slice. Accepts
// also a UUID string without dashes (as long as it's a UUID).
func clientDeviceUUIDEncode(id string) ([]byte, error) {
	const size = 16             // bytes
	const stringSize = size * 2 // two characters (encoded as hex) from a string represent a single byte
	const noDashes = 4

	// checks if the size is appropriate for a string with and without dashes for a UUID v4
	if len(id) != stringSize && len(id) != stringSize+noDashes {
		return nil, ErrInvalidInput
	}

	// remove dashes from the client device ID string
	clientDeviceIdStrTmp := strings.Split(id, "-")
	clientDeviceIdStr := strings.Join(clientDeviceIdStrTmp, "")
	buff, err := hex.DecodeString(clientDeviceIdStr)

	// the reason we didn't directly return hex.DecodeString() is because in case of an
	// error the function still returns the byte slice that it was successfully able to
	// convert. But we wished to return nil in the event of an error.
	if err != nil {
		return nil, err
	}
	return buff, nil
}

// Decodes a 16-byte client device ID byte slice into a string
func clientDeviceUUIDDecode(data []byte) (string, error) {
	clientDeviceIdDashless := hex.EncodeToString(data)

	// add dashes in the format 8-4-4-4-12
	clientDeviceId := ""

	dashOffset := []int{8, 4, 4, 4, 12}
	dashOffsetCount := 0
	for pos, char := range clientDeviceIdDashless {
		if dashOffsetCount < len(dashOffset)-1 && pos == dashOffset[dashOffsetCount] {
			dashOffsetCount++
			dashOffset[dashOffsetCount] += pos
			clientDeviceId += "-"
		}

		clientDeviceId += string(char)
	}

	return clientDeviceId, nil
}

func uint16Encode(i uint16) []byte {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, i)
	return buff
}

func uint16Decode(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, ErrInvalidInput
	}
	return binary.BigEndian.Uint16(b), nil
}

func uint8Decode(b []byte) (uint8, error) {
	if len(b) != 1 {
		return 0, ErrInvalidInput
	}
	return b[0], nil
}

func uintVarEncode(i int64) []byte {
	b := make([]byte, 6)
	binary.PutVarint(b, i)
	return b
}

func uintVarDecode(b []byte) (int64, error) {
	i, err := binary.Varint(b)
	if err <= 0 {
		return 0, ErrInvalidInput
	}
	return i, nil
}

func ipAddressEncode(ip net.IP) []byte {
	return ip
}

// Returns a net.IP type from the provided byte slice. The inputted byte slice can be either a 16 bytes long IPv6
// address or a 4 bytes IPv4 address.
func ipAddressDecode(b []byte) (net.IP, error) {
	if len(b) != 16 && len(b) != 4 {
		return nil, ErrInvalidInput
	}

	return net.IP(b), nil
}

// ipInfoEncode encodes the parameters for TypeIPInfo.
func ipInfoEncode(info IPInfo) byte {
	// 	7 6 5 4 3 2 1 0
	// 	+-+-+-+-+-+-+-+-+
	// 	|R|R|R|R|R|R|R|N|
	// 	+-+-+-+-+-+-+-+-+
	//
	// Control field bit 0: Client behind NAT (0=false, 1=true)

	b := uint8(0)

	if info.ClientBehindNAT {
		b |= 0b0000_0001
	}

	return b
}

// ipInfoEncode decodes the parameters for TypeIPInfo.
func ipInfoDecode(b byte) IPInfo {
	info := IPInfo{
		ClientBehindNAT: false,
	}

	if (b & 0x01) == 1 {
		info.ClientBehindNAT = true
	}

	return info
}
