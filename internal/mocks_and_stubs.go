package internal

import (
	"context"
	"net"

	"github.com/stretchr/testify/mock"
)

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerMock{}

type DatagramRequestHandlerMock struct {
	mock.Mock
}

func (d *DatagramRequestHandlerMock) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	d.Called(resp, r)
}

func NewDatagramRequestHandlerMock() *DatagramRequestHandlerMock {
	d := &DatagramRequestHandlerMock{}
	return d
}

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerStub{}

type DatagramRequestHandlerStub struct {
	f func(ctx context.Context, resp UDPResponser, r DatagramRequest)
}

func (d *DatagramRequestHandlerStub) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	d.f(ctx, resp, r)
}

//nolint:lll
func NewDatagramRequestHandlerStub(f func(ctx context.Context, resp UDPResponser, r DatagramRequest)) *DatagramRequestHandlerStub {
	d := &DatagramRequestHandlerStub{
		f: f,
	}
	return d
}

var _ UDPResponser = &UDPResponseMock{}

type UDPResponseMock struct {
	mock.Mock
}

func (u *UDPResponseMock) SendUDPResponse(dst net.UDPAddr, body []byte) error {
	args := u.Called(dst, body)
	return args.Error(0)
}

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
