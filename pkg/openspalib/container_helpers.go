package openspalib

import (
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

const (
	TimestampKey       uint8 = 1
	ClientUUIDKey      uint8 = 2
	TargetProtocolKey  uint8 = 3
	TargetPortStartKey uint8 = 4
	TargetPortEndKey   uint8 = 5
	ClientIPv4Key      uint8 = 6
	ClientIPv6Key      uint8 = 7
	TargetIPv4Key      uint8 = 8
	TargetIPv6Key      uint8 = 9
	NonceKey           uint8 = 10
	DurationKey        uint8 = 11
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

func TargetProtocolFromContainer(c tlv.Container) (InternetProtocolNumber, error) {
	b, ok := c.GetBytes(TargetProtocolKey)
	if !ok {
		return ProtocolUndefined, errors.Wrap(ErrMissingEntry, "no target protocol key in container")
	}

	p, err := TargetProtocolDecode(b)
	if err != nil {
		return ProtocolUndefined, errors.Wrap(err, "target protocol decode")
	}

	return p, nil
}

func TargetProtocolToContainer(c tlv.Container, p InternetProtocolNumber) error {
	b, err := TargetProtocolEncode(p)
	if err != nil {
		return errors.Wrap(err, "target protocol encode")
	}

	c.SetByte(TargetProtocolKey, b)

	return nil
}

func TargetPortStartFromContainer(c tlv.Container) (int, error) {
	b, ok := c.GetBytes(TargetPortStartKey)
	if !ok {
		return 0, errors.Wrap(ErrMissingEntry, "no target port start key in container")
	}

	p, err := TargetPortStartDecode(b)
	if err != nil {
		return 0, errors.Wrap(err, "target port start decode")
	}

	return p, nil
}

func TargetPortStartToContainer(c tlv.Container, p int) error {
	b, err := TargetPortStartEncode(p)
	if err != nil {
		return errors.Wrap(err, "target port start encode")
	}

	c.SetBytes(TargetPortStartKey, b)

	return nil
}

func TargetPortEndFromContainer(c tlv.Container) (int, error) {
	b, ok := c.GetBytes(TargetPortEndKey)
	if !ok {
		return 0, errors.Wrap(ErrMissingEntry, "no target port end key in container")
	}

	p, err := TargetPortEndDecode(b)
	if err != nil {
		return 0, errors.Wrap(err, "target port end decode")
	}

	return p, nil
}

func TargetPortEndToContainer(c tlv.Container, p int) error {
	b, err := TargetPortEndEncode(p)
	if err != nil {
		return errors.Wrap(err, "target port end encode")
	}

	c.SetBytes(TargetPortEndKey, b)

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

func TargetIPv4FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(TargetIPv4Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no target ipv4 key in container")
	}

	ip, err := IPv4Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv4 decode")
	}

	return ip, nil
}

func TargetIPv4ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv4Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv4 encode")
	}

	c.SetBytes(TargetIPv4Key, b)

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

func TargetIPv6FromContainer(c tlv.Container) (net.IP, error) {
	b, ok := c.GetBytes(TargetIPv6Key)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no target ipv6 key in container")
	}

	ip, err := IPv6Decode(b)
	if err != nil {
		return nil, errors.Wrap(err, "ipv6 decode")
	}

	return ip, nil
}

func TargetIPv6ToContainer(c tlv.Container, ip net.IP) error {
	b, err := IPv6Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv6 encode")
	}

	c.SetBytes(TargetIPv6Key, b)

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

func TargetIPFromContainer(c tlv.Container) (net.IP, error) {
	b4, ok4 := c.GetBytes(TargetIPv4Key)
	b6, ok6 := c.GetBytes(TargetIPv6Key)

	if !ok4 && !ok6 {
		return nil, errors.Wrap(ErrMissingEntry, "no target ipv4 or ipv6 key in container")
	}

	if ok4 && ok6 {
		return nil, errors.Wrap(ErrViolationOfProtocolSpec, "cannot have both target ipv4 and ipv6 in container")
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

func ClientUUIDFromContainer(c tlv.Container) (string, error) {
	b, ok := c.GetBytes(ClientUUIDKey)
	if !ok {
		return "", errors.Wrap(ErrMissingEntry, "no client uuid key in container")
	}

	id, err := ClientUUIDDecode(b)
	if err != nil {
		return "", errors.Wrap(err, "client uuid decode")
	}

	return id, nil
}

func ClientUUIDToContainer(c tlv.Container, uuid string) error {
	b, err := ClientUUIDEncode(uuid)
	if err != nil {
		return errors.Wrap(err, "client uuid encode")
	}

	c.SetBytes(ClientUUIDKey, b)

	return nil
}
