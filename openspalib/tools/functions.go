package tools

import (
	"errors"
	"net"
)

// Returns if the ip parameter string is an IPv6 address.
// In case there is no error, false signifies that it is an
// IPv4 address and true signifies that is is an IPv6 address.
func IsIPv6(ip string) (bool, error) {

	clientIPTmp := net.ParseIP(ip)

	if clientIPTmp == nil {
		return false, errors.New("bad client ip")
	}

	clientIP := clientIPTmp.To4()

	if clientIP == nil {
		return true, nil // IP is IPv6
	}

	return false, nil // IP is IPv4
}

// Checks if byte element is present in the byte slice,
// returns a boolean.
func ElementInSlice(elm byte, slice []byte) bool {

	for _, i := range slice {
		if elm == i {
			return true
		}
	}

	return false
}

// Returns true if the two byte slices match identically.
func CompareTwoByteSlices(s1, s2 []byte) bool {
	if len(s1) != len(s2) {
		return false
	}

	count := 0

	for i := range s1 {
		if s1[i] != s2[count] {
			return false
		}
		count++
	}

	return true
}
