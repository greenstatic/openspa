package ipresolver

import (
	"net"
)

type OutboundResolver interface {
	GetIPv4OutboundIP() (net.IP, error)
	GetIPv6OutboundIP() (net.IP, error)
}

type OutboundDummySocketResolver struct {
}

const dummyIPv4OutboundSocket = "1.1.1.1:80"
const dummyIPv6OutboundSocket = "[2606:4700:4700::1111]:80"

// TODO - change comment
// Returns the client's outbound IP that it uses for default routes.
// It will attempt to dial a dummy UDP connection to dummyOutboundSocket
// and return the local IP address used to create the connection.
func (_ OutboundDummySocketResolver) getOutboundIP(socket string) (net.IP, error) {
	conn, err := net.Dial("udp", socket)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	// Casts the returned socket to a UDPAddr so that we can extract
	// just the IP address.
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func (outbound *OutboundDummySocketResolver) GetIPv6OutboundIP() (net.IP, error) {
	return outbound.getOutboundIP(dummyIPv6OutboundSocket)
}

func (outbound *OutboundDummySocketResolver) GetIPv4OutboundIP() (net.IP, error) {
	return outbound.getOutboundIP(dummyIPv4OutboundSocket)
}
