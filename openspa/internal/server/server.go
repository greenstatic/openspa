package server

import (
	"crypto/rsa"
	"github.com/greenstatic/openspa/internal/extensionScripts"
	"github.com/greenstatic/openspa/internal/firewalltracker"
	"github.com/greenstatic/openspalib/request"
	"net"
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
