package tools

import (
	"errors"
	"github.com/greenstatic/openspalib"
	"strings"
)

// Returns the byte value of the protocol according to:
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml.
// If unsupported protocol, we will return an error.
func ConvertProtoStrToByte(proto string) (byte, error) {

	protocol := strings.ToUpper(proto)

	switch protocol {
	case "ICMP":
		return openspalib.Protocol_ICMP, nil
	case "TCP":
		return openspalib.Protocol_TCP, nil
	case "UDP":
		return openspalib.Protocol_UDP, nil
	case "IPV4":
		return openspalib.Protocol_IPV4, nil
	case "ICMPV6":
		return openspalib.Protocol_ICMPv6, nil
	default:
		return 0x0, errors.New("unsupported protocol")
	}

}

// The opposite of ConvertProtoStrToByte - converts a byte to
// a string. If there is no mapping we will return an empty string.
func ConvertProtoByteToStr(b byte) string {
	switch b {
	case openspalib.Protocol_ICMP:
		return "ICMP"
	case openspalib.Protocol_TCP:
		return "TCP"
	case openspalib.Protocol_UDP:
		return "UDP"
	case openspalib.Protocol_IPV4:
		return "IPV4"
	case openspalib.Protocol_ICMPv6:
		return "ICMPV6"
	default:
		return ""
	}
}

// Returns if the port can be equal to zero for the specified protocol.
func PortCanBeZero(protocol byte) bool {
	switch protocol {
	case openspalib.Protocol_TCP:
		return false
	case openspalib.Protocol_UDP:
		return false
	default:
		return true
	}
}

// Converts a signature method constant to a string.
func ConvertSignatureMethodByteToStr(b byte) string {
	switch b {
	case openspalib.SignatureMethod_RSA_SHA256:
		return "RSA_SHA256"
	default:
		return ""
	}
}
