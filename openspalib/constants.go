package openspalib

const (
	Version = 1 // version of the protocol

	// Protocol numbers are according to: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	Protocol_ICMP   = 1
	Protocol_IPV4   = 4
	Protocol_TCP    = 6
	Protocol_UDP    = 17
	Protocol_ICMPv6 = 58

	// Encryption methods
	EncryptionMethod_RSA2048_AES256CBC = 1

	// Signature methods
	SignatureMethod_RSA_SHA256 = 1
)

// Returns all the supported encryption methods
func SupportedEncryptionMethods() []byte {
	return []byte{EncryptionMethod_RSA2048_AES256CBC}
}

// Returns all the supported signature methods
func SupportedSignatureMethods() []byte {
	return []byte{SignatureMethod_RSA_SHA256}
}
