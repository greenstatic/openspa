package internal

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/pkg/errors"
)

const (
	IPTablesChainDefault = "OPENSPA-ALLOW"
)

var _ Firewall = &IPTables{}

type IPTables struct {
	c        CommandExecuter
	Settings IPTablesSettings
}

type IPTablesSettings struct {
	Chain string
}

var IPTablesSettingsDefault = IPTablesSettings{
	Chain: IPTablesChainDefault,
}

func NewIPTables(c CommandExecuter, s IPTablesSettings) *IPTables {
	ipt := &IPTables{
		c:        c,
		Settings: s,
	}

	if ipt.Settings.Chain == "" {
		panic("iptables chain is empty")
	}

	return ipt
}

func (ipt *IPTables) Check() error {
	_, err := ipt.c.Execute(iptablesCommand(), nil, "-V")
	if err != nil {
		return errors.Wrap(err, "iptables")
	}

	_, err = ipt.c.Execute(ip6tablesCommand(), nil, "-V")
	if err != nil {
		return errors.Wrap(err, "ip6tables")
	}

	_, err = ipt.c.Execute(conntrackCommand(), nil, "-V")
	if err != nil {
		return errors.Wrap(err, "conntrack")
	}

	return nil
}

func (ipt *IPTables) FirewallSetup() error {
	_, err := ipt.c.Execute(iptablesCommand(), nil, "-F", ipt.Settings.Chain)
	if err != nil {
		_, err := ipt.c.Execute(iptablesCommand(), nil, "--new-chain", ipt.Settings.Chain)
		if err != nil {
			return errors.Wrap(err, "iptables new chain")
		}
	}

	_, err = ipt.c.Execute(ip6tablesCommand(), nil, "-F", ipt.Settings.Chain)
	if err != nil {
		_, err := ipt.c.Execute(ip6tablesCommand(), nil, "--new-chain", ipt.Settings.Chain)
		if err != nil {
			return errors.Wrap(err, "ip6tables new chain")
		}
	}

	return nil
}

func (ipt *IPTables) RuleAdd(r FirewallRule, _ FirewallRuleMetadata) error {
	cmd := iptablesCommand()
	src6 := isIPv6(r.SrcIP)
	dst6 := isIPv6(r.DstIP)

	if src6 && dst6 {
		cmd = ip6tablesCommand()
	} else if src6 != dst6 {
		return errors.New("src and dst are not same ip family")
	}

	var args []string
	//nolint:gocritic
	if r.Proto == FirewallProtoTCP || r.Proto == FirewallProtoUDP {
		args = []string{
			"-A", ipt.Settings.Chain,
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
			"--dport", ipt.portString(r),
			"-j", "ACCEPT",
		}
	} else if r.Proto == FirewallProtoICMP || r.Proto == FirewallProtoICMPv6 {
		args = []string{
			"-A", ipt.Settings.Chain,
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
			"-j", "ACCEPT",
		}
	} else {
		return errors.New("unsupported protocol")
	}

	_, err := ipt.c.Execute(cmd, nil, args...)
	if err != nil {
		return errors.Wrap(err, cmd)
	}

	return nil
}

func (ipt *IPTables) RuleRemove(r FirewallRule, _ FirewallRuleMetadata) error {
	cmd := iptablesCommand()
	src6 := isIPv6(r.SrcIP)
	dst6 := isIPv6(r.DstIP)

	if src6 && dst6 {
		cmd = ip6tablesCommand()
	} else if src6 != dst6 {
		return errors.New("src and dst are not same ip family")
	}

	var iptablesArgs []string
	var conntrackArgs []string
	//nolint:gocritic
	if r.Proto == FirewallProtoTCP || r.Proto == FirewallProtoUDP {
		iptablesArgs = []string{
			"-D", ipt.Settings.Chain,
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
			"--dport", ipt.portString(r),
			"-j", "ACCEPT",
		}
		conntrackArgs = []string{
			"-D",
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
			"--dport", ipt.portString(r),
		}
	} else if r.Proto == FirewallProtoICMP || r.Proto == FirewallProtoICMPv6 {
		iptablesArgs = []string{
			"-D", ipt.Settings.Chain,
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
			"-j", "ACCEPT",
		}
		conntrackArgs = []string{
			"-D",
			"-p", r.Proto,
			"-s", r.SrcIP.String(),
			"-d", r.DstIP.String(),
		}
	} else {
		return errors.New("unsupported protocol")
	}

	_, err := ipt.c.Execute(cmd, nil, iptablesArgs...)
	if err != nil {
		return errors.Wrap(err, cmd)
	}
	_, _ = ipt.c.Execute(conntrackCommand(), nil, conntrackArgs...)

	return nil
}

func (ipt *IPTables) portString(r FirewallRule) string {
	if r.DstPortStart == r.DstPortEnd {
		return strconv.Itoa(r.DstPortStart)
	}

	if r.DstPortEnd == 0 {
		return strconv.Itoa(r.DstPortStart)
	}

	return fmt.Sprintf("%d:%d", r.DstPortStart, r.DstPortEnd)
}

func iptablesCommand() string {
	return osEnvLookupOrDefault("IPTABLES_COMMAND", "iptables")
}

func ip6tablesCommand() string {
	return osEnvLookupOrDefault("IP6TABLES_COMMAND", "ip6tables")
}

func conntrackCommand() string {
	return osEnvLookupOrDefault("CONNTRACK_COMMAND", "conntrack")
}

func osEnvLookupOrDefault(env, defaultVal string) string {
	cmd, ok := os.LookupEnv(env)
	if !ok {
		return defaultVal
	}

	return cmd
}

func execErrHandle(err error) error {
	switch e := err.(type) {
	case *exec.Error:
		return errors.Wrap(err, "execution")

	case *exec.ExitError:
		return errors.Wrap(err, "command exit code "+strconv.Itoa(e.ExitCode()))
	default:
		return errors.Wrap(err, "unknown error")
	}
}

func newIPTablesFromServerConfigFirewall(fc ServerConfigFirewall) (*IPTables, error) {
	chain := fc.IPTables.Chain

	if len(chain) == 0 {
		return nil, errors.New("missing chain")
	}

	ipt := NewIPTables(&CommandExecute{}, IPTablesSettings{
		Chain: chain,
	})

	return ipt, nil
}
