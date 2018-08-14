package extensionScripts

import (
	"bytes"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/greenstatic/openspa/internal/firewalltracker"
	"os/exec"
	"strconv"
)

type ruleAdd struct {
	rootDir string
	cmd     string
}

// Launches the RuleAdd Extension Script for a particular allowed host.
// Expects to be provided the connectionId along with the host details
// to pass on to the RuleAdd ES script. Returns an error is something
// goes wrong.
func (rule *ruleAdd) TriggerAddition(connId string, h firewalltracker.Host) error {
	if rule.cmd == "" {
		log.Error("RuleAdd struct does not contain a command string to execute")
		return errors.New("no cmd")
	}

	behindNatStr := "0"
	if h.BehindNAT {
		behindNatStr = "1"
	}

	clientIpVersion := "ipv4"
	if h.ClientIP.To4() == nil {
		clientIpVersion = "ipv6"
	}

	serverIpVersion := "ipv4"
	if h.ServerIP.To4() == nil {
		serverIpVersion = "ipv6"
	}

	cmd := exec.Command(rule.cmd,
		h.ClientDeviceID,
		clientIpVersion,
		h.ClientIP.String(),
		serverIpVersion,
		h.ServerIP.String(),
		h.Protocol,
		strconv.Itoa(h.StartPort),
		strconv.Itoa(h.EndPort),
		behindNatStr,
		strconv.Itoa(int(h.Duration)))

	cmd.Dir = rule.rootDir

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	log.WithFields(log.Fields{
		"connectionId":    connId,
		"clientDeviceId":  h.ClientDeviceID,
		"protocol":        h.Protocol,
		"startPort":       h.StartPort,
		"endPort":         h.EndPort,
		"clientBehindNat": h.BehindNAT,
		"serverIp":        h.ServerIP,
		"clientIp":        h.ClientIP,
		"duration":        h.Duration,
	}).Debug("RuleAdd is being ran for host")

	// IDEA - add the h.Date field to the debug log

	err := cmd.Run()
	if err != nil {
		log.WithFields(log.Fields{
			"connectionId":    connId,
			"clientDeviceId":  h.ClientDeviceID,
			"protocol":        h.Protocol,
			"startPort":       h.StartPort,
			"endPort":         h.EndPort,
			"clientBehindNat": h.BehindNAT,
			"serverIp":        h.ServerIP,
			"clientIp":        h.ClientIP,
			"duration":        h.Duration,
		}).Error("RuleAdd script failed to add rule")
		log.Error(err)
		log.Error(stdout.String())
		log.Error(stderr.String())
		return err
	}

	return nil
}
