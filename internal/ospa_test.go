package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOSPA(t *testing.T) {
	content := `
version: "0.2"

clientUUID: "c3b66a05-9098-4100-8141-be5695ada0e7"

# OpenSPA server
serverHost: "localhost" # can be domain or IP
serverPort: 22211

adk:
  secret: "7O4ZIRI"

crypto:
  cipherSuitePriority:
    - "CipherRSA_SHA256_AES256CBC"

  rsa:
    client:
      privateKey: |
        -----BEGIN RSA PRIVATE KEY-----
        <TODO: PRIVATE KEY CONTENTS HERE>
        -----END RSA PRIVATE KEY-----
      publicKey: |
        -----BEGIN RSA PUBLIC KEY-----
        <TODO: PUBLIC KEY CONTENTS HERE>
        -----END RSA PUBLIC KEY-----
    server:
      publicKey: |
        -----BEGIN RSA PUBLIC KEY-----
        <TODO: PUBLIC KEY CONTENTS HERE>
        -----END RSA PUBLIC KEY-----
`
	o, err := OSPAParse([]byte(content))
	assert.NoError(t, err)

	assert.Equal(t, "0.2", o.Version)
	assert.Equal(t, "c3b66a05-9098-4100-8141-be5695ada0e7", o.ClientUUID)
	assert.Equal(t, "localhost", o.ServerHost)
	assert.Equal(t, 22211, o.ServerPort)
	assert.Equal(t, "7O4ZIRI", o.ADK.Secret)
	assert.Equal(t, []string{"CipherRSA_SHA256_AES256CBC"}, o.Crypto.CipherSuitePriority)

	clientPrivKey := "-----BEGIN RSA PRIVATE KEY-----\n<TODO: PRIVATE KEY CONTENTS HERE>\n-----END RSA PRIVATE KEY-----\n"
	assert.Equal(t, clientPrivKey, o.Crypto.RSA.Client.PrivateKey)

	clientPubKey := "-----BEGIN RSA PUBLIC KEY-----\n<TODO: PUBLIC KEY CONTENTS HERE>\n-----END RSA PUBLIC KEY-----\n"
	assert.Equal(t, clientPubKey, o.Crypto.RSA.Client.PublicKey)

	serverPubKey := "-----BEGIN RSA PUBLIC KEY-----\n<TODO: PUBLIC KEY CONTENTS HERE>\n-----END RSA PUBLIC KEY-----\n"
	assert.Equal(t, serverPubKey, o.Crypto.RSA.Server.PublicKey)
}
