package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	assert.Equal(t, "iptables", sc.Firewall.Backend)
	assert.Equal(t, "OPENSPA-ALLOW", sc.Firewall.IPTables.Chain)

	assert.Equal(t, []string{"CipherRSA_SHA256_AES256CBC"}, sc.Crypto.CipherSuitePriority)
	assert.Equal(t, "/home/openspa/server/authorized", sc.Crypto.RSA.Client.PublicKeyLookupDir)
	assert.Equal(t, "/home/openspa/server/server_private.key", sc.Crypto.RSA.Server.PrivateKeyPath)
	assert.Equal(t, "/home/openspa/server/server_public.key", sc.Crypto.RSA.Server.PublicKeyPath)
}
