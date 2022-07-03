package openspalib

import "errors"

var (
	ErrInvalidBytes        = errors.New("invalid bytes")
	ErrMissingEntry        = errors.New("missing entry")
	ErrBadInput            = errors.New("bad input")
	ErrCipherSuiteRequired = errors.New("cipher suite required")
)

const (
	ProtocolICMP   InternetProtocolNumber = 1
	ProtocolIPV4   InternetProtocolNumber = 4
	ProtocolTCP    InternetProtocolNumber = 6
	ProtocolUDP    InternetProtocolNumber = 17
	ProtocolICMPv6 InternetProtocolNumber = 58

	maxTCPUDPPort = 65535
)

// InternetProtocolNumber is the protocol found in the IPv4 header field Protocol.
// See: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
type InternetProtocolNumber uint8

func (i InternetProtocolNumber) ToBin() byte {
	return uint8(i)
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

// portCanBeZero returns if the port can be equal to zero for the specified protocol.
func portCanBeZero(protocol InternetProtocolNumber) bool {
	switch protocol {
	case ProtocolTCP, ProtocolUDP:
		return false
	default:
		return true
	}
}
