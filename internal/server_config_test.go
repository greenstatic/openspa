package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:dupl
func TestServerConfig_Verify(t *testing.T) {
	content := `
server:
  ip: "0.0.0.0"
  port: 22211

  requestHandlers: 100

  http:
    enable: true
    ip: "0.0.0.0"
    port: 22212

firewall:
  backend: "iptables"
  iptables:
    chain: "OPENSPA-ALLOW"

crypto:
  cipherSuitePriority:
    - "CipherRSA_SHA256_AES256CBC"

  rsa:
    client:
      publicKeyLookupDir: "/home/openspa/server/authorized"
    server:
      privateKeyPath: "/home/openspa/server/server_private.key"
      publicKeyPath: "/home/openspa/server/server_public.key"
`
	sc, err := ServerConfigParse([]byte(content))
	assert.NoError(t, err)

	assert.Equal(t, "0.0.0.0", sc.Server.IP)
	assert.Equal(t, 22211, sc.Server.Port)
	assert.Equal(t, true, sc.Server.HTTP.Enable)
	assert.Equal(t, "0.0.0.0", sc.Server.HTTP.IP)
	assert.Equal(t, 22212, sc.Server.HTTP.Port)
	assert.Equal(t, "iptables", sc.Firewall.Backend)
	assert.Equal(t, "OPENSPA-ALLOW", sc.Firewall.IPTables.Chain)

	assert.Equal(t, []string{"CipherRSA_SHA256_AES256CBC"}, sc.Crypto.CipherSuitePriority)
	assert.Equal(t, "/home/openspa/server/authorized", sc.Crypto.RSA.Client.PublicKeyLookupDir)
	assert.Equal(t, "/home/openspa/server/server_private.key", sc.Crypto.RSA.Server.PrivateKeyPath)
	assert.Equal(t, "/home/openspa/server/server_public.key", sc.Crypto.RSA.Server.PublicKeyPath)
}

//nolint:dupl
func TestServerConfig_ParseWithDefaults(t *testing.T) {
	content := `
crypto:
  cipherSuitePriority:
    - "CipherRSA_SHA256_AES256CBC"

  rsa:
    client:
      publicKeyLookupDir: "/home/openspa/server/authorized"
    server:
      privateKeyPath: "/home/openspa/server/server_private.key"
      publicKeyPath: "/home/openspa/server/server_public.key"
`
	sc, err := ServerConfigParse([]byte(content))
	assert.NoError(t, err)

	assert.Equal(t, "::", sc.Server.IP)
	assert.Equal(t, 22211, sc.Server.Port)
	assert.Equal(t, false, sc.Server.HTTP.Enable)
	assert.Equal(t, "::", sc.Server.HTTP.IP)
	assert.Equal(t, 22212, sc.Server.HTTP.Port)

	assert.Equal(t, []string{"CipherRSA_SHA256_AES256CBC"}, sc.Crypto.CipherSuitePriority)
	assert.Equal(t, "/home/openspa/server/authorized", sc.Crypto.RSA.Client.PublicKeyLookupDir)
	assert.Equal(t, "/home/openspa/server/server_private.key", sc.Crypto.RSA.Server.PrivateKeyPath)
	assert.Equal(t, "/home/openspa/server/server_public.key", sc.Crypto.RSA.Server.PublicKeyPath)
}

func TestServerConfigFirewall(t *testing.T) {
	assert.Error(t, ServerConfigFirewall{
		Backend: "",
		IPTables: &ServerConfigFirewallIPTables{
			Chain: "zar",
		},
		Command: &ServerConfigFirewallCommand{
			RuleAdd:       "foo",
			RuleRemove:    "bar",
			FirewallSetup: "zar",
		},
	}.Verify())

	assert.Error(t, ServerConfigFirewall{
		Backend: "",
		IPTables: &ServerConfigFirewallIPTables{
			Chain: "zar",
		},
		Command: nil,
	}.Verify())

	assert.Error(t, ServerConfigFirewall{
		Backend:  ServerConfigFirewallBackendIPTables,
		IPTables: nil,
		Command:  nil,
	}.Verify())

	assert.Error(t, ServerConfigFirewall{
		Backend:  ServerConfigFirewallBackendCommand,
		IPTables: nil,
		Command:  nil,
	}.Verify())

	assert.NoError(t, ServerConfigFirewall{
		Backend:  ServerConfigFirewallBackendCommand,
		IPTables: nil,
		Command: &ServerConfigFirewallCommand{
			RuleAdd:    "foo",
			RuleRemove: "bar",
		},
	}.Verify())

	assert.Error(t, ServerConfigFirewall{
		Backend:  ServerConfigFirewallBackendIPTables,
		IPTables: nil,
		Command: &ServerConfigFirewallCommand{
			RuleAdd:    "foo",
			RuleRemove: "bar",
		},
	}.Verify())

	assert.Error(t, ServerConfigFirewall{
		Backend: ServerConfigFirewallBackendIPTables,
		IPTables: &ServerConfigFirewallIPTables{
			Chain: "zar",
		},
		Command: &ServerConfigFirewallCommand{
			RuleAdd:    "foo",
			RuleRemove: "bar",
		},
	}.Verify())

	assert.NoError(t, ServerConfigFirewall{
		Backend: ServerConfigFirewallBackendIPTables,
		IPTables: &ServerConfigFirewallIPTables{
			Chain: "zar",
		},
		Command: nil,
	}.Verify())
}

func TestServerConfigFirewallIPTables(t *testing.T) {
	assert.Error(t, ServerConfigFirewallIPTables{
		Chain: "",
	}.Verify())

	assert.NoError(t, ServerConfigFirewallIPTables{
		Chain: "foo",
	}.Verify())
}

func TestServerConfigFirewallCommand(t *testing.T) {
	assert.Error(t, ServerConfigFirewallCommand{
		FirewallSetup: "",
		RuleAdd:       "",
		RuleRemove:    "",
	}.Verify())

	assert.Error(t, ServerConfigFirewallCommand{
		FirewallSetup: "",
		RuleAdd:       "foo",
		RuleRemove:    "",
	}.Verify())

	assert.Error(t, ServerConfigFirewallCommand{
		FirewallSetup: "bar",
		RuleAdd:       "foo",
		RuleRemove:    "",
	}.Verify())

	assert.NoError(t, ServerConfigFirewallCommand{
		FirewallSetup: "",
		RuleAdd:       "foo",
		RuleRemove:    "bar",
	}.Verify())

	assert.NoError(t, ServerConfigFirewallCommand{
		FirewallSetup: "zar",
		RuleAdd:       "foo",
		RuleRemove:    "bar",
	}.Verify())

	assert.Error(t, ServerConfigFirewallCommand{
		FirewallSetup: "zar",
		RuleAdd:       "",
		RuleRemove:    "bar",
	}.Verify())

	assert.Error(t, ServerConfigFirewallCommand{
		FirewallSetup: "zar",
		RuleAdd:       "bar",
		RuleRemove:    "",
	}.Verify())
}

func TestServerConfigAuthorization(t *testing.T) {
	assert.Error(t, ServerConfigAuthorization{
		Backend: "",
		Simple: &ServerConfigAuthorizationSimple{
			Duration: "1h",
		},
		Command: &ServerConfigAuthorizationCommand{
			AuthorizationCmd: "foo",
		},
	}.Verify())

	assert.Error(t, ServerConfigAuthorization{
		Backend: "",
		Simple: &ServerConfigAuthorizationSimple{
			Duration: "1h",
		},
		Command: nil,
	}.Verify())

	assert.Error(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendSimple,
		Simple:  nil,
		Command: nil,
	}.Verify())

	assert.Error(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendCommand,
		Simple:  nil,
		Command: nil,
	}.Verify())

	assert.NoError(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendCommand,
		Simple:  nil,
		Command: &ServerConfigAuthorizationCommand{
			AuthorizationCmd: "foo",
		},
	}.Verify())

	assert.Error(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendSimple,
		Simple:  nil,
		Command: &ServerConfigAuthorizationCommand{
			AuthorizationCmd: "foo",
		},
	}.Verify())

	assert.Error(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendSimple,
		Simple: &ServerConfigAuthorizationSimple{
			Duration: "1h",
		},
		Command: &ServerConfigAuthorizationCommand{
			AuthorizationCmd: "foo",
		},
	}.Verify())

	assert.NoError(t, ServerConfigAuthorization{
		Backend: ServerConfigAuthorizationBackendSimple,
		Simple: &ServerConfigAuthorizationSimple{
			Duration: "1h",
		},
		Command: nil,
	}.Verify())
}

func TestServerConfigAuthorizationSimple(t *testing.T) {
	assert.NoError(t, ServerConfigAuthorizationSimple{Duration: "1h"}.Verify())
	assert.NoError(t, ServerConfigAuthorizationSimple{Duration: "100h"}.Verify())
	assert.NoError(t, ServerConfigAuthorizationSimple{Duration: "4660h"}.Verify())
	assert.Error(t, ServerConfigAuthorizationSimple{Duration: "4661h"}.Verify())
	assert.Error(t, ServerConfigAuthorizationSimple{Duration: "0.5s"}.Verify())
	assert.Error(t, ServerConfigAuthorizationSimple{Duration: "-1h"}.Verify())
	assert.Error(t, ServerConfigAuthorizationSimple{Duration: "1ms"}.Verify())
}
