package internal

import (
	"encoding/json"
	"net"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var _ Firewall = &FirewallCommand{}

type FirewallCommand struct {
	FirewallSetupCmd string
	RuleAddCmd       string
	RuleRemoveCmd    string

	exec CommandExecuter
}

type FirewallCommandRuleAddInput struct {
	ClientUUID     string `json:"clientUUID"`
	IPIsIPv6       bool   `json:"ipIsIPv6"`
	ClientIP       net.IP `json:"clientIP"`
	TargetIP       net.IP `json:"targetIP"`
	TargetProtocol string `json:"targetProtocol"`
	PortStart      int    `json:"portStart"`
	PortEnd        int    `json:"portEnd,omitempty"`
	Duration       int    `json:"duration"`
}

type FirewallCommandRuleRemoveInput struct {
	ClientUUID     string `json:"clientUUID"`
	IPIsIPv6       bool   `json:"ipIsIPv6"`
	ClientIP       net.IP `json:"clientIP"`
	TargetIP       net.IP `json:"targetIP"`
	TargetProtocol string `json:"targetProtocol"`
	PortStart      int    `json:"portStart"`
	PortEnd        int    `json:"portEnd,omitempty"`
}

func NewFirewallCommand(setupCmd, ruleAddCmd, ruleRemoveCmd string) *FirewallCommand {
	fc := &FirewallCommand{
		FirewallSetupCmd: setupCmd,
		RuleAddCmd:       ruleAddCmd,
		RuleRemoveCmd:    ruleRemoveCmd,
		exec:             &CommandExecute{},
	}

	return fc
}

func (fc *FirewallCommand) FirewallSetup() error {
	_, err := fc.exec.Execute(fc.FirewallSetupCmd, nil)
	return err
}

func (fc *FirewallCommand) RuleAdd(r FirewallRule, meta FirewallRuleMetadata) error {
	input := FirewallCommandRuleAddInput{
		ClientUUID:     meta.ClientUUID,
		IPIsIPv6:       isIPv6(r.SrcIP),
		ClientIP:       r.SrcIP,
		TargetIP:       r.DstIP,
		TargetProtocol: r.Proto,
		PortStart:      r.DstPortStart,
		PortEnd:        r.DstPortEnd,
		Duration:       int(meta.Duration.Seconds()),
	}

	stdin, err := json.Marshal(input)
	if err != nil {
		return errors.Wrap(err, "json marshal input")
	}

	output, err := fc.exec.Execute(fc.RuleAddCmd, stdin)
	if err != nil {
		log.Warn().Msgf("Failed to add rule %s, external command output: %s", r.String(), output)
		return errors.Wrap(err, "execute rule add command")
	}

	return nil
}

func (fc *FirewallCommand) RuleRemove(r FirewallRule, meta FirewallRuleMetadata) error {
	input := FirewallCommandRuleRemoveInput{
		ClientUUID:     meta.ClientUUID,
		IPIsIPv6:       isIPv6(r.SrcIP),
		ClientIP:       r.SrcIP,
		TargetIP:       r.DstIP,
		TargetProtocol: r.Proto,
		PortStart:      r.DstPortStart,
		PortEnd:        r.DstPortEnd,
	}

	stdin, err := json.Marshal(input)
	if err != nil {
		return errors.Wrap(err, "json marshal input")
	}

	output, err := fc.exec.Execute(fc.RuleRemoveCmd, stdin)
	if err != nil {
		log.Warn().Msgf("Failed to remove rule %s, external command output: %s", r.String(), output)
		return errors.Wrap(err, "execute rule remove command")
	}

	return nil
}
