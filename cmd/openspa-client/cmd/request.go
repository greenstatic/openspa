package cmd

import (
	"crypto/rsa"
	"github.com/greenstatic/openspalib/cryptography"
	"github.com/greenstatic/openspalib/response"
	"github.com/greenstatic/openspalib/tools"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net"
	"github.com/greenstatic/openspa/internal/client"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"github.com/greenstatic/openspa/internal/ospa"
	"os"
	"strconv"
	"time"
)

var (
	clientDeviceID       string
	useIpv6              = false
	protocol             string
	clientPrivateKeyPath string
	clientPublicKeyPath  string
	serverPublicKeyPath  string

	startPort           uint16
	endPort             uint16
	serverPort          uint16
	serverIP            net.IP
	clientIP            net.IP
	clientIPSetManually bool
	clientBehindNAT     bool
	autoMode            bool

	retryCount int
)

// TODO - This file would need to be refactored.
// The run command has gone out of hand and is too long!

var requestCmd = &cobra.Command{
	Use:   "request [OSPA file]",
	Short: "Send an OpenSPA request packet",
	Long:  `Create an OpenSPA request packet by specifying all the request packet fields`,
	Args:  cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {

		ospaFile := ospa.OSPA{}
		ospaFilePath := ""

		if len(args) == 1 {
			ospaFilePath = args[0]
			// Check if OSPA file exists
			log.WithField("file", ospaFilePath).Debug("Checking if OSPA file exists")
			if _, err := os.Stat(ospaFilePath); os.IsNotExist(err) {
				log.Error("OSPA file does not exist")
				os.Exit(badOSPAFile)
				return
			}

			content, err := ioutil.ReadFile(ospaFilePath)
			if err != nil {
				log.WithField("file", ospaFilePath).Error("OSPA file failed to open")
				os.Exit(badOSPAFile)
				return
			}

			// Parse
			ospaFile, err = ospa.Parse(content)
			if err != nil {
				log.WithField("file", ospaFilePath).Error("Failed to parse OSPA file")
				log.Error(err)
				os.Exit(badOSPAFile)
				return
			}
		}

		var clientPrivKey *rsa.PrivateKey
		var clientPubKey *rsa.PublicKey
		var serverPubKey *rsa.PublicKey

		var clientPrivKeyByteData []byte
		var clientPubKeyByteData []byte
		var serverPubKeyByteData []byte

		if ospaFile.Exists() {
			log.WithFields(log.Fields{"file": ospaFilePath, "name": ospaFile.Name}).Debug("Using OSPA file")

			clientDeviceID = ospaFile.ClientDeviceID
			if serverIP == nil {
				serverIP = ospaFile.ServerIP
			}

			if serverPort == 0 {
				serverPort = ospaFile.ServerPort
			}

			if echoIPv4Server == "" {
				echoIPv4Server = ospaFile.EchoIpServer
			}

			//if echoIPv6Server == "" {
			//	echoIPv6Server = ospaFile.EchoIpServer
			//} // TODO

			clientPrivKeyByteData = []byte(ospaFile.PrivateKeyStr)
			clientPubKeyByteData = []byte(ospaFile.PublicKeyStr)
			serverPubKeyByteData = []byte(ospaFile.ServerPublicKeyStr)
		}

		// Client's private key
		if clientPrivKeyByteData == nil {
			if clientPrivateKeyPath == "" {
				log.Error("Need to specify the client's private key path")
				os.Exit(badPrameters)
				return
			}

			log.WithField("path", clientPrivateKeyPath).Debug("Using command line flag client private key")
			tmpKeyData, err := cryptography.ReadPEMFile(clientPrivateKeyPath)
			if err != nil {
				log.Error("Failed to read client's private key")
				log.Error(err)
				os.Exit(failedToReadClientPrivateKey)
				return
			}
			clientPrivKeyByteData = tmpKeyData
		}

		clientPrivKey, err := cryptography.DecodeX509PrivateKeyRSA(clientPrivKeyByteData)
		if err != nil {
			log.Error("Failed to decode client's private key")
			log.Error(err)
			os.Exit(failedToDecodeClientPrivateKey)
			return
		}

		// Client's public key
		if clientPubKeyByteData == nil {
			if clientPublicKeyPath == "" {
				log.Error("Need to specify the client's public key path")
				os.Exit(badPrameters)
				return
			}

			log.WithField("path", clientPublicKeyPath).Debug("Using command line flag client public key")
			tmpKeyData, err := cryptography.ReadPEMFile(clientPublicKeyPath)
			if err != nil {
				log.Error("Failed to read client's public key")
				log.Error(err)
				os.Exit(failedToReadClientPublicKey)
				return
			}
			clientPubKeyByteData = tmpKeyData
		}

		clientPubKey, err = cryptography.DecodeX509PublicKeyRSA(clientPubKeyByteData)
		if err != nil {
			log.Error("Failed to decode client's public key")
			log.Error(err)
			os.Exit(failedToDecodeClientPublicKey)
			return
		}

		// Server's public key
		if serverPubKeyByteData == nil {
			if serverPublicKeyPath == "" {
				log.Error("Need to specify the server's public key path")
				os.Exit(badPrameters)
				return
			}

			log.WithField("path", serverPublicKeyPath).Debug("Using command line flag server public key")
			tmpKeyData, err := cryptography.ReadPEMFile(serverPublicKeyPath)
			if err != nil {
				log.Error("Failed to read server's public key")
				log.Error(err)
				os.Exit(failedToReadServerPublicKey)
				return
			}
			serverPubKeyByteData = tmpKeyData
		}

		serverPubKey, err = cryptography.DecodeX509PublicKeyRSA(serverPubKeyByteData)
		if err != nil {
			log.Error("Failed to decode client's public key")
			log.Error(err)
			os.Exit(failedToDecodeServerPublicKey)
			return
		}

		// Check that server IP is present
		if serverIP == nil {
			log.Error("No serverIp specified")
			os.Exit(badPrameters)
			return
		}

		// Parse protocol
		protocolByte, err := tools.ConvertProtoStrToByte(protocol)
		if err != nil {
			log.Error("Failed to parse protocol")
			log.Error(err)
			os.Exit(badPrameters)
			return
		}

		if !tools.PortCanBeZero(protocolByte) && startPort == 0 {
			log.Error("Protocol requires port")
			os.Exit(badPrameters)
			return
		}

		// Parse ports
		if endPort == 0 {
			endPort = startPort
		}

		if startPort > endPort {
			log.Error("StartPort cannot be larger than the endPort")
			os.Exit(badPrameters)
			return
		}

		// Sets flag to let us know that the command flag for providing the client's IP
		// was set
		if clientIP != nil {
			clientIPSetManually = true
		}

		requestResp := make(chan string, 1)
		request(clientPrivKey, clientPubKey, serverPubKey, protocolByte, requestResp)

		resp := <-requestResp
		switch resp {
		case "failed to resolve ips":
			os.Exit(failedToResolveIPs)
		case "failed to send or receive packet":
			os.Exit(failedToSendRequestPacket)
		case "stopped retrying":
			os.Exit(noResponseToRequestPacket)
		}
	},
}

func init() {

	requestCmd.Flags().StringVar(&clientDeviceID, "client-device-id", "", "Client Device ID (UUID)")

	requestCmd.Flags().StringVar(&protocol, "protocol", "TCP", "Protocol (ICMP, TCP, UDP)")

	requestCmd.Flags().Uint16VarP(&startPort, "port", "p", 0,
		"Start Port (eg. 22, 80, 443, etc.)")

	requestCmd.Flags().Uint16VarP(&endPort, "end-port", "", 0,
		"End Port (used in combination with Start Port to achieve port ranges, eg. 20-80)")

	requestCmd.Flags().IPVarP(&serverIP, "server-ip", "s", nil,
		"OpenSPA Server IP - Destination IP (IPv4/IPv6)")

	requestCmd.Flags().Uint16Var(&serverPort, "server-port", 0, "OpenSPA Server Port")

	requestCmd.Flags().IPVarP(&clientIP, "client-ip", "c", nil, "Client's IP - Source IP (IPv4/IPv6)")
	requestCmd.Flags().BoolVarP(&clientBehindNAT, "nat", "n", false, "Client is behind NAT, used only if clientIp flag is set")

	requestCmd.Flags().StringVar(&clientPrivateKeyPath, "private-key", "", "Client's private Key")

	requestCmd.Flags().StringVar(&clientPublicKeyPath, "public-key", "", "Client's public Key")

	requestCmd.Flags().StringVar(&serverPublicKeyPath, "server-public-key", "", "Server's public Key")

	requestCmd.Flags().IntVarP(&retryCount, "retry-count", "r", 3,
		"Number of OpenSPA request packets to send in case we do not receive a response, use -1 for infinite")

	requestCmd.Flags().BoolVarP(&autoMode, "auto-mode", "a", false,
		"Automatically send request packet when the duration from the previous request is nearing 50% before termination")

	requestCmd.Flags().StringVar(&echoIPv4Server, "echo-ipv4-server", ipresolver.DefaultEchoIpV4Server,
		"The IPv4 Echo-IP server to use for automatic public IP discovery (can be a domain or IP address)")

	requestCmd.Flags().StringVar(&echoIPv6Server, "echo-ipv6-server", ipresolver.DefaultEchoIpV6Server,
		"The IPv6 Echo-IP server to use for automatic public IP discovery (can be a domain or IP address)")

	//requestCmd.MarkFlagRequired("port")

	rootCmd.AddCommand(requestCmd)
}

// Send the request and decode the response.
// Note this function uses global variables, would be better if we
// refactored this.
func request(clientPrivKey *rsa.PrivateKey, clientPubKey *rsa.PublicKey, serverPubKey *rsa.PublicKey, protocol byte, ch chan string) {

	if serverIP.To4() == nil {
		useIpv6 = true
	}

	for {

		if clientIPSetManually {
			log.Info("Using manual client IP: %s with NAT flag set to: %s", clientIP.String(),
				strconv.FormatBool(clientBehindNAT))
		} else {
			// Use EchoIP to resolve public IP and if behind NAT
			log.WithFields(log.Fields{
				"echoIPv4Server": echoIPv4Server,
				"echoIPv6Server": echoIPv6Server,
			}).Debug("Using Echo-IP to resolve public IP")
			var err error
			ipResolverResp, err := ipresolver.Resolve(echoIPv4Server, echoIPv6Server)
			if err != nil {
				log.Error("Failed to resolve IP")
				log.Error(err)
				ch <- "failed to resolve ips"
				return
			}

			if useIpv6 {
				clientIP = ipResolverResp.PublicIPv6
				clientBehindNAT = ipResolverResp.NatIPv6
			} else {
				clientIP = ipResolverResp.PublicIPv4
				clientBehindNAT = ipResolverResp.NatIPv4
			}

			log.WithFields(log.Fields{"publicIp": clientIP, "behindNat": clientBehindNAT}).
				Info("Successfully resolved IPs")
		}

		// Create client to send the request packet
		c := client.New{
			serverIP,
			serverPort,
			clientPrivKey,
			clientPubKey,
			serverPubKey}

		packetData := client.InputPacketData{
			clientDeviceID,
			protocol,
			startPort,
			endPort,
			serverIP,
			clientIP,
			clientBehindNAT,
		}

		const retryPauseDuration = 3 // seconds
		const timeout = 10           // seconds
		stoppedRetrying := false
		var resp response.Packet

		for i := 0; i < int(retryCount); i++ {
			var err error
			resp, err = c.Send(packetData, timeout)
			if err != nil {
				if err.Error() == "failed to send" {
					// Failed to send so try again after a short pause
					if i+1 != retryCount { // in case this is the last retry skip this step
						log.WithFields(log.Fields{"try": i + 1, "total": retryCount}).
							Infof("Failed to send, retrying again in %d seconds", retryPauseDuration)

						time.Sleep(retryPauseDuration * time.Second)

						log.Debug("Retrying now")
					} else {
						log.WithFields(log.Fields{"try": i + 1, "total": retryCount}).
							Info("Failed to send")
					}
					stoppedRetrying = true
					continue
				} else {
					// Failed to send or receive packet due to unknown reason, quit
					log.Error("Failed to send or receive packet")
					log.Error(err)
					stoppedRetrying = false
					ch <- "failed to send or receive packet"
					return
				}
			} else {
				log.Info("Successfully performed OpenSPA exchange")
				stoppedRetrying = false
				break
			}
		}

		if stoppedRetrying {
			log.Error("Stopped retrying. No response, giving up.")
			ch <- "stopped retrying"
			return
		}

		// Successfully received response
		portStr := strconv.Itoa(int(resp.Payload.StartPort))
		if resp.Payload.StartPort != resp.Payload.EndPort {
			portStr += "-" + strconv.Itoa(int(resp.Payload.EndPort))
		}

		log.WithFields(log.Fields{
			"protocol": tools.ConvertProtoByteToStr(resp.Payload.Protocol),
			"startPort": resp.Payload.StartPort,
			"endPort":   resp.Payload.EndPort,
			"duration":  resp.Payload.Duration,
		}).
			Info("You have been granted access to ports")

		if autoMode {
			// Automatically send another request packet after 1/2 of the duration time
			resendIn := resp.Payload.Duration / 2 // seconds
			log.WithField("seconds", resendIn).Info("Again requesting access in a few seconds")
			time.Sleep(time.Duration(resendIn) * time.Second)
			log.Debug("Wait over, requesting access again")
			continue

		}

		ch <- "done"
		return
	}

}
