package openspalib

import (
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

const (
	TimestampKey        uint8 = 1
	ClientDeviceUUIDKey uint8 = 2
	ProtocolKey         uint8 = 3
	PortStartKey        uint8 = 4
	PortEndKey          uint8 = 5
	ClientIPv4Key       uint8 = 6
	ClientIPv6Key       uint8 = 7
	ServerIPv4Key       uint8 = 8
	ServerIPv6Key       uint8 = 9
	NonceKey            uint8 = 10
	DurationKey         uint8 = 11
)

func TimestampFromContainer(c tlv.Container) (time.Time, error) {
	b, ok := c.GetBytes(TimestampKey)
	if !ok {
		return time.Time{}, errors.Wrap(ErrMissingEntry, "no timestamp key in container")
	}

	t, err := TimestampDecode(b)
	if err != nil {
		return time.Time{}, errors.Wrap(err, "timestamp decode")
	}

	return t, nil
}

func TimestampToContainer(c tlv.Container, t time.Time) error {
	b, err := TimestampEncode(t)
	if err != nil {
		return errors.Wrap(err, "timestamp encode")
	}

	c.SetBytes(TimestampKey, b)

	return nil
}

func ProtocolFromContainer(c tlv.Container) (InternetProtocolNumber, error) {
	b, ok := c.GetBytes(ProtocolKey)
	if !ok {
		return InternetProtocolNumber(0), errors.Wrap(ErrMissingEntry, "no protocol key in container")
	}

	p, err := ProtocolDecode(b)
	if err != nil {
		return InternetProtocolNumber(0), errors.Wrap(err, "protocol decode")
	}

	return p, nil
}

func ProtocolToContainer(c tlv.Container, p InternetProtocolNumber) error {
	b, err := ProtocolEncode(p)
	if err != nil {
		return errors.Wrap(err, "protocol encode")
	}

	c.SetByte(ProtocolKey, b)

	return nil
}

func PortStartFromContainer(c tlv.Container) (int, error) {
	b, ok := c.GetBytes(PortStartKey)
	if !ok {
		return 0, errors.Wrap(ErrMissingEntry, "no port start key in container")
	}

	p, err := PortStartDecode(b)
	if err != nil {
		return 0, errors.Wrap(err, "port start decode")
	}

	return p, nil
}

func PortStartToContainer(c tlv.Container, p int) error {
	b, err := PortStartEncode(p)
	if err != nil {
		return errors.Wrap(err, "port start encode")
	}

	c.SetBytes(PortStartKey, b)

	return nil
}

func PortEndFromContainer(c tlv.Container) (int, error) {
	b, ok := c.GetBytes(PortEndKey)
	if !ok {
		return 0, errors.Wrap(ErrMissingEntry, "no port end key in container")
	}

	p, err := PortEndDecode(b)
	if err != nil {
		return 0, errors.Wrap(err, "port end decode")
	}

	return p, nil
}

func PortEndToContainer(c tlv.Container, p int) error {
	b, err := PortEndEncode(p)
	if err != nil {
		return errors.Wrap(err, "port end encode")
	}

	c.SetBytes(PortEndKey, b)

	return nil
}

func ClientIPv4FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(ClientIPv4Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no client ipv4 key in container")
	}

	ip, err := IPv4Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv4 decode")
	}

	return ip, nil
}

func ClientIPv4ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv4Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv4 encode")
	}

	c.SetBytes(ClientIPv4Key, b)

	return nil
}

func ServerIPv4FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(ServerIPv4Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no server ipv4 key in container")
	}

	ip, err := IPv4Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv4 decode")
	}

	return ip, nil
}

func ServerIPv4ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv4Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv4 encode")
	}

	c.SetBytes(ServerIPv4Key, b)

	return nil
}

func ClientIPv6FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(ClientIPv6Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no client ipv6 key in container")
	}

	ip, err := IPv6Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv6 decode")
	}

	return ip, nil
}

func ClientIPv6ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv6Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv6 encode")
	}

	c.SetBytes(ClientIPv6Key, b)

	return nil
}

func ServerIPv6FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(ServerIPv6Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no server ipv6 key in container")
	}

	ip, err := IPv6Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv6 decode")
	}

	return ip, nil
}

func ServerIPv6ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv6Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv6 encode")
	}

	c.SetBytes(ServerIPv6Key, b)

	return nil
}

func ClientIPFromContainer(c tlv.Container) (net.IP, error) {
	b4, ok4 := c.GetBytes(ClientIPv4Key)
	b6, ok6 := c.GetBytes(ClientIPv6Key)

	if !ok4 && !ok6 {
		return nil, errors.Wrap(ErrMissingEntry, "no client ipv4 or ipv6 key in container")
	}

	if ok4 && ok6 {
		return nil, errors.Wrap(ErrViolationOfProtocolSpec, "cannot have both client ipv4 and ipv6 in container")
	}

	if ok4 {
		ip, err := IPv4Decode(b4)
		if err != nil {
			return nil, errors.Wrap(err, "ipv4 decode")
		}
		return ip, nil
	}

	ip, err := IPv6Decode(b6)
	if err != nil {
		return nil, errors.Wrap(err, "ipv6 decode")
	}
	return ip, nil
}

func ServerIPFromContainer(c tlv.Container) (net.IP, error) {
	b4, ok4 := c.GetBytes(ServerIPv4Key)
	b6, ok6 := c.GetBytes(ServerIPv6Key)

	if !ok4 && !ok6 {
		return nil, errors.Wrap(ErrMissingEntry, "no server ipv4 or ipv6 key in container")
	}

	if ok4 && ok6 {
		return nil, errors.Wrap(ErrViolationOfProtocolSpec, "cannot have both server ipv4 and ipv6 in container")
	}

	if ok4 {
		ip, err := IPv4Decode(b4)
		if err != nil {
			return nil, errors.Wrap(err, "ipv4 decode")
		}
		return ip, nil
	}

	ip, err := IPv6Decode(b6)
	if err != nil {
		return nil, errors.Wrap(err, "ipv6 decode")
	}
	return ip, nil
}

func NonceFromContainer(c tlv.Container) ([]byte, error) {
	b, ok := c.GetBytes(NonceKey)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no nonce key in container")
	}
	return b, nil
}

func NonceToContainer(c tlv.Container, n []byte) error {
	b, err := NonceEncode(n)
	if err != nil {
		return errors.Wrap(err, "nonce encode")
	}

	c.SetBytes(NonceKey, b)

	return nil
}

func DurationFromContainer(c tlv.Container) (time.Duration, error) {
	b, ok := c.GetBytes(DurationKey)
	if !ok {
		return 0, errors.Wrap(ErrMissingEntry, "no duration key in container")
	}

	d, err := DurationDecode(b)
	if err != nil {
		return 0, errors.Wrap(err, "duration decode")
	}

	return d, nil
}

func DurationToContainer(c tlv.Container, d time.Duration) error {
	b, err := DurationEncode(d)
	if err != nil {
		return errors.Wrap(err, "duration encode")
	}

	c.SetBytes(DurationKey, b)

	return nil
}

func ClientDeviceUUIDFromContainer(c tlv.Container) (string, error) {
	b, ok := c.GetBytes(ClientDeviceUUIDKey)
	if !ok {
		return "", errors.Wrap(ErrMissingEntry, "no client device key in container")
	}

	id, err := ClientDeviceUUIDDecode(b)
	if err != nil {
		return "", errors.Wrap(err, "client device uuid decode")
	}

	return id, nil
}

func ClientDeviceUUIDToContainer(c tlv.Container, uuid string) error {
	b, err := ClientDeviceUUIDEncode(uuid)
	if err != nil {
		return errors.Wrap(err, "client device uuid encode")
	}

	c.SetBytes(ClientDeviceUUIDKey, b)

	return nil
}
