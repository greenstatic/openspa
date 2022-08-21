package internal

import (
	"fmt"
	"net"
)

var (
	FirewallProtoTCP = "TCP"
	FirewallProtoUDP = "UDP"
)

type FirewallRule struct {
	Proto   string
	SrcIP   net.IP
	DstIP   net.IP
	DstPort int
}

type Firewall interface {
	FirewallSetup() error
	RuleAdd(r FirewallRule) error
	RuleRemove(r FirewallRule) error
}

func (r *FirewallRule) String() string {
	return fmt.Sprintf("%s -> %s %s/%d", r.SrcIP.String(), r.DstIP.String(), r.Proto, r.DstPort)
}
