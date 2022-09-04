package internal

import (
	"github.com/stretchr/testify/mock"
)

var _ Firewall = &FirewallMock{}

type FirewallMock struct {
	mock.Mock
}

func (fw *FirewallMock) RuleAdd(r FirewallRule, meta FirewallRuleMetadata) error {
	args := fw.Called(r, meta)
	return args.Error(0)
}

func (fw *FirewallMock) RuleRemove(r FirewallRule, meta FirewallRuleMetadata) error {
	args := fw.Called(r, meta)
	return args.Error(0)
}

func (fw *FirewallMock) FirewallSetup() error {
	args := fw.Called()
	return args.Error(0)
}

var _ Firewall = FirewallStub{}

type FirewallStub struct{}

func (FirewallStub) RuleAdd(r FirewallRule, meta FirewallRuleMetadata) error {
	return nil
}

func (FirewallStub) RuleRemove(r FirewallRule, meta FirewallRuleMetadata) error {
	return nil
}

func (FirewallStub) FirewallSetup() error {
	return nil
}

var _ CommandExecuter = &CommandExecuteMock{}

type CommandExecuteMock struct {
	mock.Mock
}

func (c *CommandExecuteMock) Execute(cmd string, stdin []byte, args ...string) ([]byte, error) {
	a := c.Called(cmd, stdin, args)
	return a.Get(0).([]byte), a.Error(1)
}
