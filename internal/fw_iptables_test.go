package internal

import (
	"net"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestIPTables_Check(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []byte(nil), []string{"-V"}).Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []byte(nil), []string{"-V"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []byte(nil), []string{"-V"}).Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.Check())

	c.AssertExpectations(t)
}

func TestIPTables_IPv4RuleAddAndRemove(t *testing.T) {
	c := &CommandExecuteMock{}
	ipt := NewIPTables(c, IPTablesSettingsDefault)

	c.On("Execute", "iptables", []byte(nil), []string{
		"-A", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	r := FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(88, 200, 23, 12),
		DstIP:        net.IPv4(88, 200, 23, 3),
		DstPortStart: 443,
	}
	assert.NoError(t, ipt.RuleAdd(r, FirewallRuleMetadata{}))

	c.On("Execute", "iptables", []byte(nil), []string{
		"-D", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []byte(nil), []string{
		"-D",
		"-p", "TCP",
		"-s", "88.200.23.12",
		"-d", "88.200.23.3",
		"--dport", "443"}).Return([]byte{}, nil).Once()

	assert.NoError(t, ipt.RuleRemove(r, FirewallRuleMetadata{}))

	c.AssertExpectations(t)
}

func TestIPTables_IPv6RuleAddAndRemove(t *testing.T) {
	c := &CommandExecuteMock{}
	ipt := NewIPTables(c, IPTablesSettingsDefault)

	c.On("Execute", "ip6tables", []byte(nil), []string{
		"-A", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	r := FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.ParseIP("2001:1470:fffd:66::23:12"),
		DstIP:        net.ParseIP("2001:1470:fffd:66::23:3"),
		DstPortStart: 443,
	}
	assert.NoError(t, ipt.RuleAdd(r, FirewallRuleMetadata{}))

	c.On("Execute", "ip6tables", []byte(nil), []string{
		"-D", IPTablesChainDefault,
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443",
		"-j", "ACCEPT"}).Return([]byte{}, nil).Once()
	c.On("Execute", "conntrack", []byte(nil), []string{
		"-D",
		"-p", "TCP",
		"-s", "2001:1470:fffd:66::23:12",
		"-d", "2001:1470:fffd:66::23:3",
		"--dport", "443"}).Return([]byte{}, nil).Once()
	assert.NoError(t, ipt.RuleRemove(r, FirewallRuleMetadata{}))

	c.AssertExpectations(t)
}

func TestIPTables_PortString(t *testing.T) {
	ipt := IPTables{}

	assert.Equal(t, "0", ipt.portString(FirewallRule{
		DstPortStart: 0,
		DstPortEnd:   0,
	}))

	assert.Equal(t, "80", ipt.portString(FirewallRule{
		DstPortStart: 80,
		DstPortEnd:   0,
	}))

	assert.Equal(t, "80", ipt.portString(FirewallRule{
		DstPortStart: 80,
		DstPortEnd:   80,
	}))
	assert.Equal(t, "80:443", ipt.portString(FirewallRule{
		DstPortStart: 80,
		DstPortEnd:   443,
	}))
	assert.Equal(t, "0:65535", ipt.portString(FirewallRule{
		DstPortStart: 0,
		DstPortEnd:   65535,
	}))
}

func TestIPTables_Setup(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []byte(nil), []string{"-F", IPTablesChainDefault}).Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []byte(nil), []string{"-F", IPTablesChainDefault}).Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}

func TestIPTables_SetupWithNonExistingIPTables(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []byte(nil), []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, errors.New("simulate error")).Once()

	c.On("Execute", "iptables", []byte(nil), []string{"--new-chain", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()
	c.On("Execute", "ip6tables", []byte(nil), []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}

func TestIPTables_SetupWithNonExistingIP6Tables(t *testing.T) {
	c := &CommandExecuteMock{}

	c.On("Execute", "iptables", []byte(nil), []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	c.On("Execute", "ip6tables", []byte(nil), []string{"-F", IPTablesChainDefault}).
		Return([]byte{}, errors.New("simulate error")).Once()
	c.On("Execute", "ip6tables", []byte(nil), []string{"--new-chain", IPTablesChainDefault}).
		Return([]byte{}, nil).Once()

	ipt := NewIPTables(c, IPTablesSettingsDefault)
	assert.NoError(t, ipt.FirewallSetup())

	c.AssertExpectations(t)
}
