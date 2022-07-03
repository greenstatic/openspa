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

func FirewallPortStartFromContainer(c Container) (int, error) {
	return 0, nil
}

func FirewallPortEndFromContainer(c Container) (int, error) {
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

func ClientIPFromContainer(c Container) (net.IP, error) {
	return nil, nil
}

func DurationFromContainer(c Container) (time.Duration, error) {
	return 0, nil
}
