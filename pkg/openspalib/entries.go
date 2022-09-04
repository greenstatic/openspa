package openspalib

import (
	"encoding/binary"
	"math"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	TimestampSize      = 8
	TargetProtocolSize = 1
	TargetPortSize     = 2
	IPV4Size           = 4
	IPV6Size           = 16
	DurationSize       = 3
	ClientUUIDSize     = 16
)

func TimestampEncode(t time.Time) ([]byte, error) {
	b := make([]byte, 8)
	i := t.Unix()
	binary.BigEndian.PutUint64(b, uint64(i))
	return b, nil
}

func TimestampDecode(b []byte) (time.Time, error) {
	if len(b) != TimestampSize {
		return time.Time{}, ErrInvalidBytes
	}

	i := binary.BigEndian.Uint64(b)
	t := time.Unix(int64(i), 0)

	return t.UTC(), nil
}

func TargetProtocolEncode(p InternetProtocolNumber) (byte, error) {
	return p.ToBin(), nil
}

func TargetProtocolDecode(b []byte) (InternetProtocolNumber, error) {
	if len(b) != TargetProtocolSize {
		return ProtocolUndefined, ErrInvalidBytes
	}

	return InternetProtocolFromNumber(b[0])
}

func TargetPortStartEncode(p int) ([]byte, error) {
	if err := convertableToUint16(p); err != nil {
		return nil, errors.Wrap(err, "uint16 conversion")
	}
	return uint16Encode(uint16(p))
}
func TargetPortEndEncode(p int) ([]byte, error) {
	return TargetPortStartEncode(p)
}

func convertableToUint16(i int) error {
	if i < 0 {
		return errors.Wrap(ErrBadInput, "cannot convert negative integers")
	}

	if math.Log2(float64(i)) >= 16 {
		return errors.Wrap(ErrBadInput, "too large for uint16")
	}
	return nil
}

func uint16Encode(i uint16) ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b, nil
}

func uint16Decode(b []byte) (uint16, error) {
	const size = 2 // bytes

	if len(b) > size || len(b) == 0 {
		return 0, ErrInvalidBytes
	}

	if len(b) == 1 {
		bTemp := make([]byte, 2)
		bTemp[0] = 0
		bTemp[1] = b[0]
		b = bTemp
	}

	return binary.BigEndian.Uint16(b), nil
}

func TargetPortStartDecode(b []byte) (int, error) {
	i, err := uint16Decode(b)
	return int(i), err
}

func TargetPortEndDecode(b []byte) (int, error) {
	return TargetPortStartDecode(b)
}

func IPv4Encode(ip net.IP) ([]byte, error) {
	ip = ip.To4()
	if !isIPv4(ip) || ip == nil {
		return nil, errors.Wrap(ErrBadInput, "input is not ipv4 address")
	}
	b := []byte(ip)
	return b, nil
}

func IPv4Decode(b []byte) (net.IP, error) {
	if len(b) != IPV4Size {
		return nil, ErrInvalidBytes
	}

	ip := net.IP(b)

	ip = ip.To4()
	if !isIPv4(ip) {
		return nil, errors.Wrap(ErrBadInput, "input is not ipv4 address")
	}

	return ip, nil
}

func IPv6Encode(ip net.IP) ([]byte, error) {
	ip = ip.To16()
	if !isIPv6(ip) || ip == nil {
		return nil, errors.Wrap(ErrBadInput, "input is not ipv6 address")
	}
	b := []byte(ip)
	return b, nil
}

func IPv6Decode(b []byte) (net.IP, error) {
	if len(b) != IPV6Size {
		return nil, ErrInvalidBytes
	}

	ip := net.IP(b)
	ip = ip.To16()
	if !isIPv6(ip) {
		return nil, errors.Wrap(ErrBadInput, "input is not ipv6 address")
	}

	return ip, nil
}

func isIPv4(ip net.IP) bool {
	return !isIPv6(ip)
}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}

var maxDuration = int(math.Pow(2, 8*DurationSize)) - 1

func DurationEncode(d time.Duration) ([]byte, error) {
	s := int(d.Seconds())
	if s > maxDuration {
		return nil, errors.Wrap(ErrBadInput, "duration too long")
	}

	if s < 1 {
		return nil, errors.Wrap(ErrBadInput, "duration too small")
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(s))

	return []byte{b[1], b[2], b[3]}, nil
}

func DurationDecode(b []byte) (time.Duration, error) {
	if len(b) != DurationSize {
		return time.Duration(0), ErrInvalidBytes
	}

	bCpy := make([]byte, 4)
	bCpy[0] = 0
	bCpy[1] = b[0]
	bCpy[2] = b[1]
	bCpy[3] = b[2]

	i := binary.BigEndian.Uint32(bCpy)

	return time.Second * time.Duration(i), nil
}

func ClientUUIDEncode(u string) ([]byte, error) {
	id, err := uuid.FromString(u)
	if err != nil {
		return nil, errors.Wrap(err, "uuid decode")
	}

	return id.Bytes(), nil
}

func ClientUUIDDecode(b []byte) (string, error) {
	if len(b) != ClientUUIDSize {
		return "", ErrInvalidBytes
	}

	u, err := uuid.FromBytes(b)
	if err != nil {
		return "", errors.Wrap(err, "uuid decode")
	}

	return u.String(), nil
}
