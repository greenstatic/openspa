package internal

import (
	"net"
	"os"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Verifier interface {
	Verify() error
}

type ServerConfig struct {
	Server        ServerConfigServer        `yaml:"server"`
	Firewall      ServerConfigFirewall      `yaml:"firewall"`
	Authorization ServerConfigAuthorization `yaml:"authorization"`
	Crypto        ServerConfigCrypto        `yaml:"crypto"`
}

type ServerConfigServer struct {
	IP              string                 `yaml:"ip"`
	Port            int                    `yaml:"port"`
	RequestHandlers int                    `yaml:"requestHandlers"`
	HTTP            ServerConfigServerHTTP `yaml:"http"`
	ADK             ServerConfigADK        `yaml:"adk"`
}

type ServerConfigServerHTTP struct {
	Enable bool   `yaml:"enable"`
	IP     string `yaml:"ip"`
	Port   int    `yaml:"port"`
}

type ServerConfigADK struct {
	Secret string             `yaml:"secret"`
	XDP    ServerConfigADKXDP `yaml:"xdp"`
}

const (
	ServerConfigADKXDPModeSKB    = "skb"
	ServerConfigADKXDPModeDriver = "driver"
	// ServerConfigADKXDPModeHW     = "hw"
)

type ServerConfigADKXDP struct {
	Mode       string   `yaml:"mode"`
	Interfaces []string `yaml:"interfaces"`
}

const (
	ServerConfigFirewallBackendIPTables = "iptables"
	ServerConfigFirewallBackendCommand  = "command"
	ServerConfigFirewallBackendNone     = "none" // used for performance measurements, not for production workload
)

type ServerConfigFirewall struct {
	Backend  string                        `yaml:"backend"`
	IPTables *ServerConfigFirewallIPTables `yaml:"iptables"`
	Command  *ServerConfigFirewallCommand  `yaml:"command"`
}

type ServerConfigFirewallIPTables struct {
	Chain string `yaml:"chain"`
}

type ServerConfigFirewallCommand struct {
	RuleAdd       string `yaml:"ruleAdd"`
	RuleRemove    string `yaml:"ruleRemove"`
	FirewallSetup string `yaml:"firewallSetup,omitempty"` // optional
}

const (
	ServerConfigAuthorizationBackendSimple  = "simple"
	ServerConfigAuthorizationBackendCommand = "command"
	ServerConfigAuthorizationBackendNone    = "none" // used for performance measurements, not for production workload
)

type ServerConfigAuthorization struct {
	Backend string                            `yaml:"backend"`
	Simple  *ServerConfigAuthorizationSimple  `yaml:"simple"`
	Command *ServerConfigAuthorizationCommand `yaml:"command"`
}

type ServerConfigAuthorizationSimple struct {
	Duration string `yaml:"duration"`
}

type ServerConfigAuthorizationCommand struct {
	AuthorizationCmd string `yaml:"authorizationCmd"`
}

type ServerConfigCrypto struct {
	CipherSuitePriority []string              `yaml:"cipherSuitePriority"`
	RSA                 ServerConfigCryptoRSA `yaml:"rsa"`
}

type ServerConfigCryptoRSA struct {
	Client ServerConfigCryptoRSAClient `yaml:"client"`
	Server ServerConfigCryptoRSAServer `yaml:"server"`
}

type ServerConfigCryptoRSAClient struct {
	PublicKeyLookupDir string `yaml:"publicKeyLookupDir"`
}

type ServerConfigCryptoRSAServer struct {
	PrivateKeyPath string `yaml:"privateKeyPath"`
	PublicKeyPath  string `yaml:"publicKeyPath"`
}

func (s ServerConfig) Verify() error {
	if err := s.Server.Verify(); err != nil {
		return errors.Wrap(err, "server")
	}

	if err := s.Firewall.Verify(); err != nil {
		return errors.Wrap(err, "firewall")
	}

	if err := s.Authorization.Verify(); err != nil {
		return errors.Wrap(err, "authorization")
	}

	if err := s.Crypto.Verify(); err != nil {
		return errors.Wrap(err, "crypto")
	}

	return nil
}
func (s ServerConfigServer) Verify() error {
	if ip := net.ParseIP(s.IP); ip == nil {
		return errors.New("invalid ip")
	}

	if s.Port == 0 {
		return errors.New("invalid port")
	}

	if s.RequestHandlers < 0 {
		return errors.New("invalid request handlers")
	}

	if err := s.HTTP.Verify(); err != nil {
		return errors.Wrap(err, "http")
	}

	if err := s.ADK.Verify(); err != nil {
		return errors.Wrap(err, "adk")
	}

	return nil
}

func (s ServerConfigServerHTTP) Verify() error {
	if s.Enable {
		if ip := net.ParseIP(s.IP); ip == nil {
			return errors.New("invalid http ip")
		}

		if s.Port == 0 {
			return errors.New("invalid port")
		}
	}
	return nil
}

func (s ServerConfigADK) Verify() error {
	if len(s.Secret) > 0 {
		if len(s.Secret) != openspalib.ADKSecretEncodedLen {
			return errors.New("encoded secret should be length 7")
		}
	}

	if err := s.XDP.Verify(); err != nil {
		return errors.Wrap(err, "xdp")
	}

	return nil
}

func (s ServerConfigADKXDP) Verify() error {
	modeErr := serverConfigADKXDPValidMode(s.Mode)

	if s.Mode == "" && len(s.Interfaces) > 0 {
		return nil
	}

	if s.Mode == "" && len(s.Interfaces) != 0 {
		return errors.New("missing mode")
	}

	if modeErr == nil && len(s.Interfaces) == 0 {
		return errors.New("missing interfaces")
	}

	return nil
}

func (s ServerConfigFirewall) Verify() error {
	switch s.Backend {
	case ServerConfigFirewallBackendIPTables:
		if s.IPTables == nil {
			return errors.New("iptables field is missing")
		}

		if s.Command != nil {
			return errors.New("command is defined while using iptables backend")
		}

		if err := s.IPTables.Verify(); err != nil {
			return errors.Wrap(err, "iptables")
		}

	case ServerConfigFirewallBackendCommand:
		if s.Command == nil {
			return errors.New("command field is missing")
		}

		if s.IPTables != nil {
			return errors.New("iptables is defined while using command backend")
		}

		if err := s.Command.Verify(); err != nil {
			return errors.Wrap(err, "command")
		}

	case ServerConfigFirewallBackendNone:
		return nil

	default:
		return errors.New("invalid backend")
	}

	return nil
}

func (s ServerConfigFirewallIPTables) Verify() error {
	if len(s.Chain) == 0 {
		return errors.New("chain parameter is empty")
	}
	return nil
}

func (s ServerConfigFirewallCommand) Verify() error {
	//nolint:staticcheck
	if len(s.FirewallSetup) == 0 {
		// It's okay if the firewall setup command is empty, it is optional
	}

	if len(s.RuleAdd) == 0 {
		return errors.New("rule add is empty")
	}

	if len(s.RuleRemove) == 0 {
		return errors.New("rule remove is empty")
	}

	return nil
}

func (s ServerConfigAuthorization) Verify() error {
	switch s.Backend {
	case ServerConfigAuthorizationBackendSimple:
		if s.Simple == nil {
			return errors.New("simple field is missing")
		}

		if s.Command != nil {
			return errors.New("command is defined while using simple backend")
		}

		if err := s.Simple.Verify(); err != nil {
			return errors.Wrap(err, "simple")
		}

	case ServerConfigAuthorizationBackendCommand:
		if s.Command == nil {
			return errors.New("command field is missing")
		}

		if s.Simple != nil {
			return errors.New("simple is defined while using command backend")
		}

		if err := s.Command.Verify(); err != nil {
			return errors.Wrap(err, "command")
		}

	case ServerConfigAuthorizationBackendNone:
		return nil

	default:
		return errors.New("invalid backend")
	}

	return nil
}

func (s ServerConfigAuthorizationSimple) Verify() error {
	d, err := time.ParseDuration(s.Duration)
	if err != nil {
		return errors.Wrap(err, "duration parse")
	}

	if d.Seconds() < 1 {
		return errors.New("duration is shorter than a second")
	}

	if d.Seconds() > float64(openspalib.DurationMax) {
		return errors.New("duration is longer than max allowed duration")
	}

	return nil
}

func (s ServerConfigAuthorizationSimple) GetDuration() time.Duration {
	d, err := time.ParseDuration(s.Duration)
	if err != nil {
		panic(err)
	}
	return d
}

func (s ServerConfigAuthorizationCommand) Verify() error {
	if s.AuthorizationCmd == "" {
		return errors.New("authorization cmd empty")
	}

	return nil
}

func (s ServerConfigCrypto) Verify() error {
	if len(s.CipherSuitePriority) == 0 {
		return errors.New("cipherSuitePriority empty")
	}

	for _, cs := range s.CipherSuitePriority {
		if crypto.CipherSuiteStringToID(cs) == crypto.CipherUnknown {
			return errors.New("cipherSuitePriority unsupported/unknown cipher: " + cs)
		}
	}

	if err := s.RSA.Verify(); err != nil {
		return errors.Wrap(err, "rsa")
	}
	return nil
}

func (s ServerConfigCryptoRSA) Verify() error {
	if err := s.Client.Verify(); err != nil {
		return errors.Wrap(err, "client")
	}
	if err := s.Server.Verify(); err != nil {
		return errors.Wrap(err, "server")
	}
	return nil
}

func (s ServerConfigCryptoRSAClient) Verify() error {
	if _, err := os.Stat(s.PublicKeyLookupDir); errors.Is(err, os.ErrNotExist) {
		return errors.New("public key lookup dir does not exist")
	}
	return nil
}

func (s ServerConfigCryptoRSAServer) Verify() error {
	if _, err := os.Stat(s.PrivateKeyPath); errors.Is(err, os.ErrNotExist) {
		return errors.New("private key path file does not exist")
	}
	if _, err := os.Stat(s.PublicKeyPath); errors.Is(err, os.ErrNotExist) {
		return errors.New("public key path file does not exist")
	}
	return nil
}

// Merge sc -> s.
func (s ServerConfig) Merge(sc ServerConfig) ServerConfig {
	f := s

	if sc.Server.IP != "" {
		f.Server.IP = sc.Server.IP
	}

	if sc.Server.Port != 0 {
		f.Server.Port = sc.Server.Port
	}

	f.Server.RequestHandlers = sc.Server.RequestHandlers

	f.Server.HTTP.Enable = sc.Server.HTTP.Enable

	if len(sc.Server.HTTP.IP) > 0 {
		f.Server.HTTP.IP = sc.Server.HTTP.IP
	}

	if sc.Server.HTTP.Port != 0 {
		f.Server.HTTP.IP = sc.Server.HTTP.IP
	}

	if len(sc.Server.ADK.Secret) != 0 {
		f.Server.ADK = sc.Server.ADK
	}

	f.Firewall = sc.Firewall
	f.Authorization = sc.Authorization
	f.Crypto = sc.Crypto

	return f
}

func ServerConfigParse(b []byte) (ServerConfig, error) {
	sc := ServerConfig{}
	if err := yaml.Unmarshal(b, &sc); err != nil {
		return ServerConfig{}, errors.Wrap(err, "yaml unmarshal")
	}

	d := DefaultServerConfig()

	return d.Merge(sc), nil
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerConfigServer{
			IP:              "::",
			Port:            openspalib.DefaultServerPort,
			RequestHandlers: NoRequestHandlersDefault,
			HTTP: ServerConfigServerHTTP{
				Enable: true,
				IP:     "::",
				Port:   ServerHTTPPortDefault,
			},
			ADK: ServerConfigADK{
				Secret: "",
				XDP: ServerConfigADKXDP{
					Mode:       "",
					Interfaces: nil,
				},
			},
		},
	}
}

func serverConfigADKXDPValidMode(m string) error {
	switch m {
	// case ServerConfigADKXDPModeSKB, ServerConfigADKXDPModeDriver, ServerConfigADKXDPModeHW:
	case ServerConfigADKXDPModeSKB, ServerConfigADKXDPModeDriver:
		return nil
	default:
		return errors.New("unsupported mode")
	}
}
