package internal

import (
	"fmt"
	"net"
	"time"
)

var (
	FirewallProtoTCP = "TCP"
	FirewallProtoUDP = "UDP"
)

type FirewallRule struct {
	Proto        string
	SrcIP        net.IP
	DstIP        net.IP
	DstPortStart int
	DstPortEnd   int
}

type FirewallRuleMetadata struct {
	ClientUUID string
	Duration   time.Duration
}

type Firewall interface {
	FirewallSetup() error
	RuleAdd(r FirewallRule, meta FirewallRuleMetadata) error
	RuleRemove(r FirewallRule, meta FirewallRuleMetadata) error
}

func (r *FirewallRule) String() string {
	s := fmt.Sprintf("%s -> %s %s/%d", r.SrcIP.String(), r.DstIP.String(), r.Proto, r.DstPortStart)
	if r.DstPortEnd != r.DstPortStart && r.DstPortEnd != 0 {
		return fmt.Sprintf("%s-%d", s, r.DstPortEnd)
	}
	return s
}
