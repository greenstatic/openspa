package ipresolver

import (
	"errors"
	"net"
)

// If the outbound IP is equal to the public IP then we are not behind
// a NAT otherwise we most probably are.
func IsBehindNAT(outbound net.IP, public net.IP) (bool, error) {
	if outbound == nil {
		return false, errors.New("outboundIP required")
	}

	if public == nil {
		return false, errors.New("publicIP required")
	}

	return !(outbound.String() == public.String()), nil
}
