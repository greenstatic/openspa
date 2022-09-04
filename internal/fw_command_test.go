package internal

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/stretchr/testify/assert"
)

func TestFirewallCommand_FirewallSetup(t *testing.T) {
	fc := NewFirewallCommand("setup-cmd", "rule-add", "rule-remove")
	exec := &CommandExecuteMock{}
	fc.exec = exec

	exec.On("Execute", "setup-cmd", []byte(nil), []string(nil)).Return([]byte{}, nil).Once()
	assert.NoError(t, fc.FirewallSetup())

	exec.AssertExpectations(t)
}

func TestFirewallCommand_RuleAdd(t *testing.T) {
	fc := NewFirewallCommand("setup-cmd", "rule-add", "rule-remove")
	exec := &CommandExecuteMock{}
	fc.exec = exec

	uuid := openspalib.RandomUUID()

	input := FirewallCommandRuleAddInput{
		ClientUUID:     uuid,
		IPIsIPv6:       false,
		ClientIP:       net.IPv4(88, 200, 12, 32),
		TargetIP:       net.IPv4(88, 200, 98, 23),
		TargetProtocol: FirewallProtoTCP,
		PortStart:      80,
		PortEnd:        1000,
		Duration:       60 * 60, // 1 Hour
	}

	stdin, err := json.Marshal(input)
	assert.NoError(t, err)

	exec.On("Execute", "rule-add", stdin, []string(nil)).Return([]byte(nil), nil).Once()
	assert.NoError(t, fc.RuleAdd(FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(88, 200, 12, 32),
		DstIP:        net.IPv4(88, 200, 98, 23),
		DstPortStart: 80,
		DstPortEnd:   1000,
	}, FirewallRuleMetadata{
		ClientUUID: uuid,
		Duration:   time.Hour,
	}))

	exec.AssertExpectations(t)
}

func TestFirewallCommand_RuleRemove(t *testing.T) {
	fc := NewFirewallCommand("setup-cmd", "rule-add", "rule-remove")
	exec := &CommandExecuteMock{}
	fc.exec = exec

	uuid := openspalib.RandomUUID()

	input := FirewallCommandRuleRemoveInput{
		ClientUUID:     uuid,
		IPIsIPv6:       false,
		ClientIP:       net.IPv4(88, 200, 12, 32),
		TargetIP:       net.IPv4(88, 200, 98, 23),
		TargetProtocol: FirewallProtoTCP,
		PortStart:      80,
		PortEnd:        1000,
	}

	stdin, err := json.Marshal(input)
	assert.NoError(t, err)

	exec.On("Execute", "rule-remove", stdin, []string(nil)).Return([]byte(nil), nil).Once()
	assert.NoError(t, fc.RuleRemove(FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(88, 200, 12, 32),
		DstIP:        net.IPv4(88, 200, 98, 23),
		DstPortStart: 80,
		DstPortEnd:   1000,
	}, FirewallRuleMetadata{
		ClientUUID: uuid,
		Duration:   time.Hour,
	}))

	exec.AssertExpectations(t)
}
