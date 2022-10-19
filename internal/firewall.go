package internal

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

var (
	FirewallProtoTCP    = "TCP"
	FirewallProtoUDP    = "UDP"
	FirewallProtoICMP   = "ICMP"
	FirewallProtoICMPv6 = "ICMPv6"
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

func NewFirewallFromServerConfigFirewall(fc ServerConfigFirewall) (Firewall, error) {
	switch fc.Backend {
	case ServerConfigFirewallBackendIPTables:
		return newIPTablesFromServerConfigFirewall(fc)
	case ServerConfigFirewallBackendCommand:
		return newFirewallCommandFromServerConfigFirewall(fc)
	case ServerConfigFirewallBackendNone:
		return firewallDummy{}, nil
	}

	return nil, errors.New("unsupported firewall backend")
}

// firewallDummy does nothing, it is just used to satisfy the interface definition. It is mostly used
// for testing/performance measurement purposes. Do not use for production work.
type firewallDummy struct{}

func (f firewallDummy) FirewallSetup() error {
	return nil
}

func (f firewallDummy) RuleAdd(r FirewallRule, meta FirewallRuleMetadata) error {
	return nil
}

func (f firewallDummy) RuleRemove(r FirewallRule, meta FirewallRuleMetadata) error {
	return nil
}
