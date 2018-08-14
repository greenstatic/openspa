package server

import (
	"crypto/rsa"
	"errors"
	"github.com/greenstatic/openspalib/cryptography"
	"github.com/greenstatic/openspalib/request"
	"github.com/greenstatic/openspalib/response"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"net"
	"github.com/greenstatic/openspa/internal/firewalltracker"
	"strconv"
	"time"
)

func (n *New) Receive() error {

	socket := net.JoinHostPort(n.IP.String(), strconv.Itoa(int(n.Port)))

	packetConn, err := net.ListenPacket("udp", socket)
	if err != nil {
		log.Error("Failed to listen on socket")
		log.Fatal(err)
		return err
	}

	defer packetConn.Close()

	// We could make this more efficient by spawning multiple packetConn.ReadFrom workers
	// however we believe that spawning a goroutine per read packet is efficient enough.
	for {

		if !n.FirewallState.AcceptNewConnections {
			log.Info("Stopping server")
			return nil
		}

		readBuffer := make([]byte, readRequestBufferSize)
		packetLength, address, _ := packetConn.ReadFrom(readBuffer)

		// Run in a separate goroutine allowing for concurrent requests
		// to be handled.
		go func() {
			senderIp, senderPort, err := net.SplitHostPort(address.String())
			if err != nil {
				log.WithField("socket", address.String()).Error("Failed to parse sender socket")
				log.Error(err)
				return
			}

			log.WithFields(log.Fields{
				"clientIp":   senderIp,
				"clientPort": senderPort,
				"packetSize": packetLength,
			}).
				Debug("Received packet from client")

			respData, err := n.processPacket(readBuffer[:packetLength])
			if err != nil {
				return
			}

			if len(respData) == 0 {
				log.Debug("No response data to send, ignoring packet")
				return
			}

			log.WithFields(log.Fields{
				"clientIp":   senderIp,
				"clientPort": senderPort,
				"packetSize": len(respData),
			}).
				Debug("Sending response packet back to client")
			packetConn.WriteTo(respData, address)
		}()
	}
}

// Takes a byte slice (which should be the received packet) and tries to decode
// it as an OpenSPA request packet. If successfully decoded verify the packet.
// The response is an OpenSPA response packet as a byte slice in case everything
// is verified and the client is authorized.
func (n *New) processPacket(data []byte) ([]byte, error) {

	packet, err := request.Decode(data, n.PrivateKey)
	if err != nil {
		log.WithField("decodeError", err).Debug("Failed to decode packet")
		return nil, err
	}

	clientID := packet.Payload.ClientDeviceID
	log.WithField("clientDeviceId", clientID).
		Debug("Getting the user's public key to verify packet")

	// Get the user's public key
	clientPubKey, err := n.ExtensionScripts.GetUserDirectoryService().UserPublicKey(clientID)
	if err != nil {
		log.Error(err)
		return nil, errors.New("failed to get user's public key")
	}

	// TODO - if clientPubKey is null return with no packet data since they are not authorized

	// Verify signature
	signatureValid := cryptography.RSA_SHA256_signature_verify(packet.ByteData, clientPubKey, packet.Signature)

	if !signatureValid {
		log.WithField("clientDeviceId", clientID).Warning("Request packet signature invalid")
		return nil, errors.New("signature invalid")
	}

	return n.initiateRequestPipeline(packet, clientPubKey)
}

// This is the request pipeline once we verify a packet. Authorization, triggering
// the creation of a firewall rule and everything is handled here.
func (n *New) initiateRequestPipeline(packet request.Packet, clientPubKey *rsa.PublicKey) ([]byte, error) {

	clientDeviceId := packet.Payload.ClientDeviceID
	// Authorization ES
	duration, err := n.ExtensionScripts.GetAuthorization().AuthUser(packet)
	if err != nil {
		log.WithField("clientDeviceId", clientDeviceId).Error("Failed to authorize user")
		return nil, err
	}

	if duration == 0 {
		log.WithField("clientDeviceId", clientDeviceId).Debug("User is not authorized")
		return nil, nil
	}

	log.WithFields(log.Fields{
		"clientDeviceId": clientDeviceId,
		"duration":       duration,
	}).Debug("User is authorized")

	// Generate a connectionId for the firewall tracker
	connIdUUID, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	connId := connIdUUID.String()

	// Create a new firewall connection tracker
	host := firewalltracker.Host{
		packet.Payload.ClientDeviceID,
		packet.Payload.ClientPublicIP,
		packet.Payload.ServerPublicIP,
		packet.Payload.ProtocolToString(),
		int(packet.Payload.StartPort),
		int(packet.Payload.EndPort),
		packet.Payload.ClientBehindNat,
		time.Now(),
		int(duration),
	}

	if err := n.FirewallState.AddHost(connId, host); err != nil {
		// Failed to add host, do not create response packet
		return nil, err
	}

	// Prepare response packet
	resp := response.New{
		packet.Payload.Protocol,
		packet.Payload.StartPort,
		packet.Payload.EndPort,
		duration,
		packet.Payload.SignatureMethod,
		packet.Header.EncryptionMethod,
	}

	respPacket, err := resp.Create()
	if err != nil {
		log.WithFields(log.Fields{
			"clientDeviceId": clientDeviceId,
			"connectionId":   connId,
		}).Error("Failed to create response packet")
		log.Error(err)
		return nil, err
	}

	// Sign response packet
	_, err = respPacket.SignatureData()
	if err != nil {
		log.WithFields(log.Fields{
			"clientDeviceId": clientDeviceId,
			"connectionId":   connId,
		}).Error("Failed to generate signature response packet data")
		log.Error(err)
		return nil, err
	}

	err = respPacket.Sign_RSA_SHA256(n.PrivateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"clientDeviceId": clientDeviceId,
			"connectionId":   connId,
		}).Error("Failed to sign response packet")
		log.Error(err)
		return nil, err
	}

	// Encrypt response packet
	err = respPacket.Encrypt_RSA_2048_With_AES_256_CBC(clientPubKey)
	if err != nil {
		log.WithFields(log.Fields{
			"clientDeviceId": clientDeviceId,
			"connectionId":   connId,
		}).Error("Failed to encrypt response packet")
		log.Error(err)
		return nil, err
	}

	// Export to a byte slice the response packet
	respData, err := respPacket.Export()
	if err != nil {
		log.WithFields(log.Fields{
			"clientDeviceId": clientDeviceId,
			"connectionId":   connId,
		}).Error("Failed to export response packet")
		log.Error(err)
		return nil, err
	}

	log.WithFields(log.Fields{
		"clientDeviceId": clientDeviceId,
		"connectionId":   connId,
		"clientIp":       packet.Payload.ClientPublicIP.String(),
		"protocol":       respPacket.Payload.ProtocolToString(),
		"startPort":      respPacket.Payload.StartPortToString(),
		"endPort":        respPacket.Payload.EndPortToString(),
		"duration":       respPacket.Payload.Duration,
	}).Info("Successfully created response packet")

	return respData, nil
}
