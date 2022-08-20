package firewall

import (
	"fmt"
	"net"
)

var (
	ProtoTCP = "TCP"
	ProtoUDP = "UDP"
)

type Rule struct {
	Proto   string
	SrcIP   net.IP
	DstIP   net.IP
	DstPort int
}

type Firewall interface {
	FirewallSetup() error
	RuleAdd(r Rule) error
	RuleRemove(r Rule) error
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s -> %s %s/%d", r.SrcIP.String(), r.DstIP.String(), r.Proto, r.DstPort)
}
