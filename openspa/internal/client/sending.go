package client

import (
	"errors"
	"fmt"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/request"
	"github.com/greenstatic/openspalib/response"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

// Based on the inputted InputPacketData create a request and send it to the
// server. After the duration of the timeout parameter (in seconds), we will
// close the connection and return an error.
func (n *New) Send(pd InputPacketData, timeout uint) (response.Packet, error) {

	sendSocket := net.JoinHostPort(n.ServerIP.String(), strconv.Itoa(int(n.ServerPort)))

	conn, err := net.Dial("udp", sendSocket)
	if err != nil {
		fmt.Printf("failed to dial sending socket %s, error: %v\n", sendSocket, err)
		return response.Packet{}, errors.New("failed to send")
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)) // sets deadline equal to the timeout

	// Create packet
	packetData, err := n.CreatePacket(pd)
	if err != nil {
		log.Error("Failed to create OpenSPA request packet")
		log.Error(err)
		return response.Packet{}, err
	}

	// Send request packet
	log.WithField("packetSize", len(packetData)).Info("Sending OpenSPA request packet")
	conn.Write(packetData)

	// Wait for response packet
	log.Debug("Waiting for OpenSPA response packet")
	buffer := make([]byte, readResponseBufferSize)
	packetLength, err := conn.Read(buffer)
	if err != nil {
		log.Info("Failed to read response from socket")
		log.Info(err)
		return response.Packet{}, errors.New("failed to send")
	}

	respDataByte := buffer[:packetLength]
	log.WithField("packetSize", packetLength).Info("Received OpenSPA response packet")

	return response.Decode(respDataByte, n.ClientPrivateKey)
}

// Returns a byte slice that represents the OpenSPA request packet.
func (n *New) CreatePacket(pd InputPacketData) ([]byte, error) {

	reqNew := request.New{
		pd.ClientDeviceID,
		pd.Protocol,
		pd.StartPort,
		pd.EndPort,
		openspalib.SignatureMethod_RSA_SHA256,
		pd.ClientBehindNAT,
		pd.ClientIP,
		pd.ServerIP,
		openspalib.EncryptionMethod_RSA2048_AES256CBC,
	}

	packet, err := reqNew.Create()
	if err != nil {
		return nil, err
	}

	// Sign the packet
	log.Debug("Signing request packet data")
	_, err = packet.SignatureData()
	if err != nil {
		return nil, err
	}

	err = packet.Sign_RSA_SHA256(n.ClientPrivateKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the packet
	log.WithField("encryptionMethod", openspalib.EncryptionMethod_RSA2048_AES256CBC).
		Debug("Encrypting request packet data")
	err = packet.Encrypt_RSA_2048_With_AES_256_CBC(n.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	packetData, err := packet.Export()
	if err != nil {
		return nil, err
	}

	log.Debug("Successfully created request packet")

	return packetData, nil
}
