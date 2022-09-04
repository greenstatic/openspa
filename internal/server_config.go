package internal

import (
	"net"
	"os"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Verifier interface {
	Verify() error
}

type ServerConfig struct {
	Server   ServerConfigServer   `yaml:"server"`
	Firewall ServerConfigFirewall `yaml:"firewall"`
	Crypto   ServerConfigCrypto   `yaml:"crypto"`
}

type ServerConfigServer struct {
	IP              string                 `yaml:"ip"`
	Port            int                    `yaml:"port"`
	RequestHandlers int                    `yaml:"requestHandlers"`
	HTTP            ServerConfigServerHTTP `yaml:"http"`
}

type ServerConfigServerHTTP struct {
	Enable bool   `yaml:"enable"`
	IP     string `yaml:"ip"`
	Port   int    `yaml:"port"`
}

const (
	ServerConfigFirewallBackendIPTables = "iptables"
	ServerConfigFirewallBackendCommand  = "command"
)

type ServerConfigFirewall struct {
	Backend  string                       `yaml:"backend"`
	IPTables ServerConfigFirewallIPTables `yaml:"iptables"`
	Command  ServerConfigFirewallCommand  `yaml:"command"`
}

type ServerConfigFirewallIPTables struct {
	Chain string `yaml:"chain"`
}

type ServerConfigFirewallCommand struct {
	RuleAdd    string `yaml:"ruleAdd"`
	RuleRemove string `yaml:"ruleRemove"`
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

	if s.RequestHandlers <= 0 {
		return errors.New("invalid request handlers")
	}

	if err := s.HTTP.Verify(); err != nil {
		return errors.Wrap(err, "http")
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

func (s ServerConfigFirewall) Verify() error {
	switch s.Backend {
	case ServerConfigFirewallBackendIPTables:
		if err := s.IPTables.Verify(); err != nil {
			return errors.Wrap(err, "iptables")
		}
	case ServerConfigFirewallBackendCommand:
		if err := s.Command.Verify(); err != nil {
			return errors.Wrap(err, "command")
		}
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
	if len(s.RuleAdd) == 0 {
		return errors.New("rule add is empty")
	}

	if len(s.RuleRemove) == 0 {
		return errors.New("rule remove is empty")
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

	if sc.Server.RequestHandlers != 0 {
		f.Server.RequestHandlers = sc.Server.RequestHandlers
	}

	f.Server.HTTP.Enable = sc.Server.HTTP.Enable

	if len(sc.Server.HTTP.IP) > 0 {
		f.Server.HTTP.IP = sc.Server.HTTP.IP
	}

	if sc.Server.HTTP.Port != 0 {
		f.Server.HTTP.IP = sc.Server.HTTP.IP
	}

	if sc.Firewall.Backend != "" {
		f.Firewall.Backend = sc.Firewall.Backend
	}

	if sc.Firewall.IPTables.Chain != "" {
		f.Firewall.IPTables.Chain = sc.Firewall.IPTables.Chain
	}

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
			RequestHandlers: 100,
			HTTP: ServerConfigServerHTTP{
				Enable: true,
				IP:     "::",
				Port:   ServerHTTPPortDefault,
			},
		},
		Firewall: ServerConfigFirewall{
			Backend: ServerConfigFirewallBackendIPTables,
			IPTables: ServerConfigFirewallIPTables{
				Chain: IPTablesChainDefault,
			},
		},
		// Crypto is missing on purpose
	}
}
