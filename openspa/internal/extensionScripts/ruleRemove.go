package extensionScripts

import (
	"bytes"
	"errors"
	"github.com/greenstatic/openspa/internal/firewalltracker"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"strconv"
)

type ruleRemove struct {
	rootDir string
	cmd     string
}

// Launches the RuleRemove Extension Script for a particular connectionId
// in use by an allowed host. Expects to be provided the connectionId
// along with the host details to pass on to the RuleRemove ES script.
// Returns an error is something goes wrong.
func (rule *ruleRemove) TriggerExpiration(connId string, h firewalltracker.Host) error {

	if rule.cmd == "" {
		log.Error("RuleRemove struct does not contain a command string to execute")
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
	}).Debug("RuleRemove is being ran for host")

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
		}).Error("RuleRemove script failed to remove rule")
		log.Error(err)
		log.Error(stdout.String())
		log.Error(stderr.String())
		return err
	}

	return nil
}
