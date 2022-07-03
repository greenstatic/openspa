package openspalib_old

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net"
)

var (
	ErrBadIP = errors.New("bad ip address")
)

// Returns if the specified byte is present in the byte slice.
func byteInSlice(elm byte, slice []byte) bool {
	return bytes.IndexByte(slice, elm) >= 0
}

// Returns if the ip parameter string is an IPv6 address. In case there is no error, false signifies that it is an
// IPv4 address and true signifies that is is an IPv6 address.
func isIPv6(ip string) (bool, error) {
	clientIPTmp := net.ParseIP(ip)

	if clientIPTmp == nil {
		return false, ErrBadIP
	}

	clientIP := clientIPTmp.To4()

	if clientIP == nil {
		return true, nil // IP is IPv6
	}

	return false, nil // IP is IPv4
}

func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil
}

func randomByteSlice(noBytes int) []byte {
	b := make([]byte, noBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return b
}
