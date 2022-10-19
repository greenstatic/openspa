package internal

import (
	"encoding/json"
	"net"
	"time"

	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type AuthorizationStrategy interface {
	RequestAuthorization(request tlv.Container) (time.Duration, error)
}

var _ AuthorizationStrategy = AuthorizationStrategySimple{}

// AuthorizationStrategySimple authorizes any form of request as long as it is authenticated successfully
// (authentication should be performed externally).
type AuthorizationStrategySimple struct {
	dur time.Duration
}

func NewAuthorizationStrategyAllow(duration time.Duration) *AuthorizationStrategySimple {
	a := &AuthorizationStrategySimple{
		dur: duration,
	}
	return a
}

func (a AuthorizationStrategySimple) RequestAuthorization(_ tlv.Container) (time.Duration, error) {
	return a.dur, nil
}

var _ AuthorizationStrategy = AuthorizationStrategyCommand{}

type AuthorizationStrategyCommand struct {
	AuthorizeCmd string

	exec CommandExecuter
}

type AuthorizationStrategyCommandAuthorizeInput struct {
	ClientUUID      string `json:"clientUUID"`
	IPIsIPv6        bool   `json:"ipIsIPv6"`
	ClientIP        net.IP `json:"clientIP"`
	TargetIP        net.IP `json:"targetIP"`
	TargetProtocol  string `json:"targetProtocol"`
	TargetPortStart int    `json:"targetPortStart"`
	TargetPortEnd   int    `json:"targetPortEnd"`
}

type AuthorizationStrategyCommandAuthorizeOutput struct {
	Duration int `json:"duration"`
}

func NewAuthorizationStrategyCommand(cmd string) *AuthorizationStrategyCommand {
	a := &AuthorizationStrategyCommand{
		AuthorizeCmd: cmd,

		exec: &CommandExecute{},
	}
	return a
}

func (a AuthorizationStrategyCommand) RequestAuthorization(c tlv.Container) (time.Duration, error) {
	i, err := a.authorizeInputGenerate(c)
	if err != nil {
		return 0, err
	}

	stdin, err := json.Marshal(i)
	if err != nil {
		return 0, errors.Wrap(err, "json marshal AuthorizationStrategyCommand stdin input")
	}

	stdout, err := a.exec.Execute(a.AuthorizeCmd, stdin)
	out := AuthorizationStrategyCommandAuthorizeOutput{}
	if err := json.Unmarshal(stdout, &out); err != nil {
		log.Info().Msgf("Authorize command output: %s", string(stdout))
		return 0, errors.Wrap(err, "json unmarshal AuthorizationStrategyCommand stdout output")
	}

	log.Debug().Msgf("Authorize command output: %s", string(stdout))
	if err != nil {
		return 0, errors.Wrap(err, "executing authorization command "+a.AuthorizeCmd)
	}

	d := time.Duration(out.Duration) * time.Second
	return d, nil
}

//nolint:lll
func (a AuthorizationStrategyCommand) authorizeInputGenerate(c tlv.Container) (AuthorizationStrategyCommandAuthorizeInput, error) {
	fwd, err := lib.RequestFirewallDataFromContainer(c)
	if err != nil {
		return AuthorizationStrategyCommandAuthorizeInput{}, errors.Wrap(err, "request firewall data from container")
	}

	i := AuthorizationStrategyCommandAuthorizeInput{
		ClientUUID:      fwd.ClientUUID,
		IPIsIPv6:        isIPv6(fwd.TargetIP),
		ClientIP:        fwd.ClientIP,
		TargetIP:        fwd.TargetIP,
		TargetProtocol:  fwd.TargetProtocol.String(),
		TargetPortStart: fwd.TargetPortStart,
		TargetPortEnd:   fwd.TargetPortEnd,
	}

	return i, nil
}

func NewAuthorizationStrategyFromServerConfigAuthorization(s ServerConfigAuthorization) (AuthorizationStrategy, error) {
	switch s.Backend {
	case ServerConfigAuthorizationBackendSimple:
		return NewAuthorizationStrategyAllow(s.Simple.GetDuration()), nil

	case ServerConfigAuthorizationBackendCommand:
		return NewAuthorizationStrategyCommand(s.Command.AuthorizationCmd), nil

	case ServerConfigAuthorizationBackendNone:
		return authorizationStrategyDummy{}, nil
	}

	return nil, errors.New("unsupported authorization backend")
}

// authorizationStrategyDummy does nothing, it is just used to satisfy the interface definition. It is mostly used
// for testing/performance measurement purposes. Do not use for production work.
type authorizationStrategyDummy struct{}

func (a authorizationStrategyDummy) RequestAuthorization(request tlv.Container) (time.Duration, error) {
	return 3 * time.Second, nil
}
