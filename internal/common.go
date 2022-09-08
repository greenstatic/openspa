package internal

import (
	"bytes"
	"os/exec"
)

type CommandExecuter interface {
	Execute(cmd string, stdin []byte, args ...string) ([]byte, error)
}

var _ CommandExecuter = &CommandExecute{}

type CommandExecute struct{}

func (c *CommandExecute) Execute(cmd string, stdin []byte, args ...string) ([]byte, error) {
	cmnd := exec.Command(cmd, args...)
	cmnd.Stdin = bytes.NewBuffer(stdin)

	out, err := cmnd.Output()
	if err != nil {
		return nil, execErrHandle(err)
	}

	return out, nil
}
