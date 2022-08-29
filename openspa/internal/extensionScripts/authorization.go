package extensionScripts

import (
	"bytes"
	"errors"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/greenstatic/openspa/openspalib/request"
	log "github.com/sirupsen/logrus"
)

type authorization struct {
	rootDir string
	cmd     string
}

// Launches the Authorization Extension Script for a particular request packet
// and returns the duration the client is authorized access for.
func (auth *authorization) AuthUser(packet request.Packet) (duration uint16, err error) {
	if auth.cmd == "" {
		log.Error("Authorization struct does not contain a command string to execute")
		return 0, errors.New("no cmd")
	}

	cmd := exec.Command(auth.cmd,
		packet.Payload.ClientDeviceID,
		packet.Payload.ClientPublicIP.String(),
		packet.Payload.ServerPublicIP.String(),
		packet.Payload.ProtocolToString(),
		packet.Payload.StartPortToString(),
		packet.Payload.EndPortToString(),
		packet.Payload.TimestampToString(),
		packet.Payload.SignatureMethodToString(),
		packet.Payload.BehindNATToString())

	cmd.Dir = auth.rootDir

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	clientDeviceId := packet.Payload.ClientDeviceID
	log.WithField("clientDeviceId", clientDeviceId).Debug("Authorization script is authorizing user")

	err = cmd.Run()
	if err != nil {
		log.WithField("clientDeviceId", clientDeviceId).
			Error("Authorization script responded with a failure")
		log.Error(err)
		log.Error(stdout.String())
		log.Error(stderr.String())
		return 0, err
	}

	var validDuration = regexp.MustCompile(`^[0-9]+`)
	durationStr := validDuration.FindString(stdout.String())

	dur, err := strconv.Atoi(durationStr)
	if err != nil {
		log.WithField("clientDeviceId", clientDeviceId).
			Error("Authorization script returned an invalid integer for the duration of authorization")
		return 0, errors.New("failed to convert duration from stdout to integer")
	}

	duration = uint16(dur)
	if duration > 0 {
		log.WithField("clientDeviceId", clientDeviceId).
			Debug("Client can access the service with the specified duration")
		return
	}

	log.WithField("clientDeviceId", clientDeviceId).
		Debug("Client cannot access the service (duration 0)")
	return
}
