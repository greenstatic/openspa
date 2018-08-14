package ipresolver

import (
	log "github.com/sirupsen/logrus"
	"net"
)

type ResolveResponse struct {
	OutboundIPv4 net.IP
	OutboundIPv6 net.IP

	PublicIPv4 net.IP
	ProxyIPv4  net.IP
	NatIPv4    bool

	PublicIPv6 net.IP
	ProxyIPv6  net.IP
	NatIPv6    bool

	NoIPv4Outbound bool
	NoIPv4Public   bool

	NoIPv6Outbound bool
	NoIPv6Public   bool
}

// Returns various network related IP addresses.
func Resolve(echoIPServerIPv4, echoIPServerIPv6 string) (ResolveResponse, error) {
	resp := ResolveResponse{}

	// Get outbound IPv4
	dummySocket := OutboundDummySocketResolver{}
	outboundIPv4, err := dummySocket.GetIPv4OutboundIP()
	if err != nil {
		log.Debug("No network connectivity for IPv4 outbound test")
		log.Debug(err)
		resp.NoIPv4Outbound = true
	}
	resp.OutboundIPv4 = outboundIPv4

	// Get outbound IPv6
	outboundIPv6, err := dummySocket.GetIPv6OutboundIP()
	if err != nil {
		log.Debug("No network connectivity for IPv6 outbound test")
		log.Debug(err)
		resp.NoIPv6Outbound = true
	}
	resp.OutboundIPv6 = outboundIPv6

	// Get public IPv4
	publicIPv4, proxyIPv4, err := EchoIPPublicResolver{}.GetPublicIP(echoIPServerIPv4)
	if err != nil {
		log.WithField("echoIpServer", echoIPServerIPv4).
			Debug("Failed to connect to Echo-IP resolver using IPv4")
		log.Debug(err)
		resp.NoIPv4Public = true
	}
	resp.PublicIPv4 = publicIPv4
	resp.ProxyIPv4 = proxyIPv4

	// Get public IPv6
	publicIPv6, proxyIPv6, err := EchoIPPublicResolver{}.GetPublicIP(echoIPServerIPv6)
	if err != nil {
		log.WithField("echoIpServer", echoIPServerIPv6).
			Debug("Failed to connect to Echo-IP resolver using IPv6")
		log.Debug(err)
		resp.NoIPv6Public = true
	}
	resp.PublicIPv6 = publicIPv6
	resp.ProxyIPv6 = proxyIPv6

	resp.NatIPv4, _ = IsBehindNAT(outboundIPv4, publicIPv4)
	resp.NatIPv6, _ = IsBehindNAT(outboundIPv6, publicIPv6)

	return resp, nil
}
