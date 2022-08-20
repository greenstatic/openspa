package firewall

import (
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestIPTables_Check(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []string{"-V"}).Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []string{"-V"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []string{"-V"}).Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.Check())

	c.AssertExpectations(t)
}

func TestIPTables_IPv4RuleAddAndRemove(t *testing.T) {
	c := &CommandExecuteMock{}
	ipt := NewIPTables(c, IPTablesSettingsDefault)

	c.On("Execute", "iptables", []string{
		"-A", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	r := Rule{
		Proto:   ProtoTCP,
		SrcIP:   net.IPv4(88, 200, 23, 12),
		DstIP:   net.IPv4(88, 200, 23, 3),
		DstPort: 443,
	}
	assert.NoError(t, ipt.RuleAdd(r))

	c.On("Execute", "iptables", []string{
		"-D", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []string{
		"-D",
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443"}).Return([]byte{}, nil).Once()

	assert.NoError(t, ipt.RuleRemove(r))

	c.AssertExpectations(t)
}

func TestIPTables_IPv6RuleAddAndRemove(t *testing.T) {
	c := &CommandExecuteMock{}
	ipt := NewIPTables(c, IPTablesSettingsDefault)

	c.On("Execute", "ip6tables", []string{
		"-A", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	r := Rule{
		Proto:   ProtoTCP,
		SrcIP:   net.ParseIP("2001:1470:fffd:66::23:12"),
		DstIP:   net.ParseIP("2001:1470:fffd:66::23:3"),
		DstPort: 443,
	}
	assert.NoError(t, ipt.RuleAdd(r))

	c.On("Execute", "ip6tables", []string{
		"-D", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []string{
		"-D",
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443"}).Return([]byte{}, nil).Once()
	assert.NoError(t, ipt.RuleRemove(r))

	c.AssertExpectations(t)
}

func TestIPTables_Setup(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []string{"-F", IPTablesChainDefault}).Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []string{"-F", IPTablesChainDefault}).Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}

func TestIPTables_SetupWithNonExistingIPTables(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, errors.New("simulate error")).Once()

	c.On("Execute", "iptables", []string{"--new-chain", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}

func TestIPTables_SetupWithNonExistingIP6Tables(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	c.On("Execute", "ip6tables", []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, errors.New("simulate error")).Once()
	c.On("Execute", "ip6tables", []string{"--new-chain", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}
