package firewall

import (
	"github.com/stretchr/testify/mock"
)

var _ Firewall = &FirewallMock{}

type FirewallMock struct {
	mock.Mock
}

func (fw *FirewallMock) RuleAdd(r Rule) error {
	args := fw.Called(r)
	return args.Error(0)
}

func (fw *FirewallMock) RuleRemove(r Rule) error {
	args := fw.Called(r)
	return args.Error(0)
}

func (fw *FirewallMock) FirewallSetup() error {
	args := fw.Called()
	return args.Error(0)
}

var _ Firewall = FirewallStub{}

type FirewallStub struct{}

func (_ FirewallStub) RuleAdd(r Rule) error {
	return nil
}

func (_ FirewallStub) RuleRemove(r Rule) error {
	return nil
}

func (_ FirewallStub) FirewallSetup() error {
	return nil
}

var _ CommandExecuter = &CommandExecuteMock{}

type CommandExecuteMock struct {
	mock.Mock
}

func (c *CommandExecuteMock) Execute(cmd string, args ...string) ([]byte, error) {
	a := c.Called(cmd, args)
	return a.Get(0).([]byte), a.Error(1)
}
