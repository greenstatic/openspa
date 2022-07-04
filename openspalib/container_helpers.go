package openspalib

import (
	"net"
	"time"

	"github.com/pkg/errors"
)

func TimestampFromContainer(c Container) (time.Time, error) {
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

func TimestampToContainer(c Container, t time.Time) error {
	b, err := TimestampEncode(t)
	if err != nil {
		return errors.Wrap(err, "timestamp encode")
	}

	c.SetBytes(TimestampKey, b)

	return nil
}

func ProtocolFromContainer(c Container) (InternetProtocolNumber, error) {
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

func ProtocolToContainer(c Container, p InternetProtocolNumber) error {
	b, err := ProtocolEncode(p)
	if err != nil {
		return errors.Wrap(err, "protocol encode")
	}

	c.SetByte(ProtocolKey, b)

	return nil
}

func PortStartFromContainer(c Container) (int, error) {
	return 0, nil
}

func PortEndFromContainer(c Container) (int, error) {
	return 0, nil
}

func ClientIPv4FromContainer(c Container) (net.IP, error) {
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

func ClientIPv4ToContainer(c Container, ip net.IP) error {
	b, err := IPv4Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv4 encode")
	}

	c.SetBytes(ClientIPv4Key, b)

	return nil
}

func ServerIPv4FromContainer(c Container) (net.IP, error) {
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

func ServerIPv4ToContainer(c Container, ip net.IP) error {
	b, err := IPv4Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv4 encode")
	}

	c.SetBytes(ServerIPv4Key, b)

	return nil
}

func ClientIPv6FromContainer(c Container) (net.IP, error) {
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

func ClientIPv6ToContainer(c Container, ip net.IP) error {
	b, err := IPv6Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv6 encode")
	}

	c.SetBytes(ClientIPv6Key, b)

	return nil
}

func ServerIPv6FromContainer(c Container) (net.IP, error) {
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

func ServerIPv6ToContainer(c Container, ip net.IP) error {
	b, err := IPv6Encode(ip)
	if err != nil {
		return errors.Wrap(err, "ipv6 encode")
	}

	c.SetBytes(ServerIPv6Key, b)

	return nil
}

func ClientIPFromContainer(c Container) (net.IP, error) {
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

func ServerIPFromContainer(c Container) (net.IP, error) {
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

func DurationFromContainer(c Container) (time.Duration, error) {
	return 0, nil
}

func NonceFromContainer(c Container) ([]byte, error) {
	b, ok := c.GetBytes(NonceKey)
	if !ok {
		return nil, errors.Wrap(ErrMissingEntry, "no nonce key in container")
	}
	return b, nil
}

func NonceToContainer(c Container, n []byte) error {
	b, err := NonceEncode(n)
	if err != nil {
		return errors.Wrap(err, "nonce encode")
	}

	c.SetBytes(NonceKey, b)

	return nil
}
