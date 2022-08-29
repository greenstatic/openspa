package server

import (
	"crypto/rsa"
	"net"

	"github.com/greenstatic/openspa/openspa/internal/extensionScripts"
	"github.com/greenstatic/openspa/openspa/internal/firewalltracker"
	"github.com/greenstatic/openspa/openspalib/request"
)

const (
	readRequestBufferSize = request.MaxSize
)

type New struct {
	IP               net.IP
	Port             uint16
	PrivateKey       *rsa.PrivateKey
	PublicKey        *rsa.PublicKey
	ExtensionScripts extensionScripts.Scripts
	FirewallState    *firewalltracker.State
	Replay           *ReplayDetect
}
