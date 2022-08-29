package client

import (
	"crypto/rsa"
	"net"

	"github.com/greenstatic/openspa/openspalib/response"
)

const (
	readResponseBufferSize = response.MaxSize
)

type New struct {
	ServerIP         net.IP
	ServerPort       uint16
	ClientPrivateKey *rsa.PrivateKey
	ClientPublicKey  *rsa.PublicKey
	ServerPublicKey  *rsa.PublicKey
}

type InputPacketData struct {
	ClientDeviceID  string
	Protocol        byte
	StartPort       uint16
	EndPort         uint16
	ServerIP        net.IP
	ClientIP        net.IP
	ClientBehindNAT bool
}
