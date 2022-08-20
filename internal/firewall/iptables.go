package firewall

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

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
	_, err := ipt.c.Execute(iptablesCommand(), "-V")
	if err != nil {
		return errors.Wrap(err, "iptables")
	}

	_, err = ipt.c.Execute(ip6tablesCommand(), "-V")
	if err != nil {
		return errors.Wrap(err, "ip6tables")
	}

	_, err = ipt.c.Execute(conntrackCommand(), "-V")
	if err != nil {
		return errors.Wrap(err, "conntrack")
	}

	return nil
}

func (ipt *IPTables) FirewallSetup() error {
	_, err := ipt.c.Execute(iptablesCommand(), "-F", ipt.Settings.Chain)
	if err != nil {
		_, err := ipt.c.Execute(iptablesCommand(), "--new-chain", ipt.Settings.Chain)
		if err != nil {
			return errors.Wrap(err, "iptables new chain")
		}
	}

	_, err = ipt.c.Execute(ip6tablesCommand(), "-F", ipt.Settings.Chain)
	if err != nil {
		_, err := ipt.c.Execute(ip6tablesCommand(), "--new-chain", ipt.Settings.Chain)
		if err != nil {
			return errors.Wrap(err, "ip6tables new chain")
		}
	}

	return nil
}

func (ipt *IPTables) RuleAdd(r Rule) error {
	cmd := iptablesCommand()
	src6 := isIPv6(r.SrcIP)
	dst6 := isIPv6(r.DstIP)

	if src6 && dst6 {
		cmd = ip6tablesCommand()
	} else if src6 != dst6 {
		return errors.New("src and dst are not same ip family")
	}

	_, err := ipt.c.Execute(cmd,
		"-A", ipt.Settings.Chain,
		"-p", r.Proto,
		"-s", r.SrcIP.String(),
		"-d", r.DstIP.String(),
		"--dport", strconv.Itoa(r.DstPort),
		"-j", "ACCEPT")

	if err != nil {
		return errors.Wrap(err, cmd)
	}
	return nil
}

func (ipt *IPTables) RuleRemove(r Rule) error {
	cmd := iptablesCommand()
	src6 := isIPv6(r.SrcIP)
	dst6 := isIPv6(r.DstIP)

	if src6 && dst6 {
		cmd = ip6tablesCommand()
	} else if src6 != dst6 {
		return errors.New("src and dst are not same ip family")
	}

	_, err := ipt.c.Execute(cmd,
		"-D", ipt.Settings.Chain,
		"-p", r.Proto,
		"-s", r.SrcIP.String(),
		"-d", r.DstIP.String(),
		"--dport", strconv.Itoa(r.DstPort),
		"-j", "ACCEPT")

	if err != nil {
		return errors.Wrap(err, cmd)
	}
	_, _ = ipt.c.Execute(conntrackCommand(),
		"-D",
		"-p", r.Proto,
		"-s", r.SrcIP.String(),
		"-d", r.DstIP.String(),
		"--dport", strconv.Itoa(r.DstPort))

	return nil
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

type CommandExecuter interface {
	Execute(cmd string, args ...string) ([]byte, error)
}

var _ CommandExecuter = &CommandExecute{}

type CommandExecute struct{}

func (c *CommandExecute) Execute(cmd string, args ...string) ([]byte, error) {
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return nil, execErrHandle(err)
	}

	return out, nil
}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}
