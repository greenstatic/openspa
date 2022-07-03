package openspalib

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func TimestampEncode(t time.Time) ([]byte, error) {
	b := make([]byte, 8)
	i := t.Unix()
	binary.BigEndian.PutUint64(b, uint64(i))
	return b, nil
}

func TimestampDecode(b []byte) (time.Time, error) {
	const timestampSize = 8 // bytes

	if len(b) != timestampSize {
		return time.Time{}, ErrInvalidBytes
	}

	i := binary.BigEndian.Uint64(b)
	t := time.Unix(int64(i), 0)

	return t.UTC(), nil
}

func ProtocolEncode(p InternetProtocolNumber) (byte, error) {
	return p.ToBin(), nil
}

func ProtocolDecode(b []byte) (InternetProtocolNumber, error) {
	const protocolSize = 1

	if len(b) != protocolSize {
		return InternetProtocolNumber(0), ErrInvalidBytes
	}

	return InternetProtocolNumber(b[0]), nil
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
	const ipv4Size = 4 // bytes

	if len(b) != ipv4Size {
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
	const ipv6Size = 16 // bytes

	if len(b) != ipv6Size {
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
