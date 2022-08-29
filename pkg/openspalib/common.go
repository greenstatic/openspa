package openspalib

import (
	"errors"
	"strings"

	uuid "github.com/satori/go.uuid"
)

var (
	ErrInvalidBytes            = errors.New("invalid bytes")
	ErrMissingEntry            = errors.New("missing entry")
	ErrBadInput                = errors.New("bad input")
	ErrViolationOfProtocolSpec = errors.New("violation of protocol spec")
	ErrCipherSuiteRequired     = errors.New("cipher suite required")
	ErrPDUTooLarge             = errors.New("pdu too large")
)

const (
	DefaultServerPort = 22211
	MaxPDUSize        = 1444
)

var (
	ProtocolUndefined = InternetProtocolNumber{
		Number:   0,
		Protocol: "",
	}
	ProtocolICMP = InternetProtocolNumber{
		Number:   1,
		Protocol: "ICMP",
	}
	ProtocolIPV4 = InternetProtocolNumber{
		Number:   4,
		Protocol: "IPv4",
	}
	ProtocolTCP = InternetProtocolNumber{
		Number:   6,
		Protocol: "TCP",
	}
	ProtocolUDP = InternetProtocolNumber{
		Number:   17,
		Protocol: "UDP",
	}
	ProtocolICMPv6 = InternetProtocolNumber{
		Number:   58,
		Protocol: "ICMPv6",
	}
)

// InternetProtocolNumber is the protocol found in the IPv4 header field Protocol.
// See: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type InternetProtocolNumber struct {
	Number   uint8
	Protocol string
}

func (i InternetProtocolNumber) ToBin() byte {
	return i.Number
}

func (i InternetProtocolNumber) String() string {
	return i.Protocol
}

// InternetProtocolNumberSupported returns a slice of InternetProtocolNumber that are supported.
func InternetProtocolNumberSupported() []InternetProtocolNumber {
	return []InternetProtocolNumber{
		ProtocolICMP,
		ProtocolIPV4,
		ProtocolTCP,
		ProtocolUDP,
		ProtocolICMPv6,
	}
}

func InternetProtocolFromString(s string) (InternetProtocolNumber, error) {
	for _, p := range InternetProtocolNumberSupported() {
		if strings.EqualFold(p.Protocol, s) {
			proto := p
			return proto, nil
		}
	}

	return ProtocolUndefined, errors.New("non supported protocol")
}

func InternetProtocolFromNumber(i uint8) (InternetProtocolNumber, error) {
	for _, p := range InternetProtocolNumberSupported() {
		if p.Number == i {
			proto := p
			return proto, nil
		}
	}

	return ProtocolUndefined, errors.New("non supported protocol")
}

// portCanBeZero returns if the port can be equal to zero for the specified protocol.
func portCanBeZero(protocol InternetProtocolNumber) bool {
	switch protocol {
	case ProtocolTCP, ProtocolUDP:
		return false
	default:
		return true
	}
}

func RandomUUID() string {
	return uuid.NewV4().String()
}
