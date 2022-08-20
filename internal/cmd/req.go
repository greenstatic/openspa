package cmd

import (
	"fmt"
	"net"
	"time"

	"github.com/greenstatic/openspa/internal"
	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var ReqCmd = &cobra.Command{
	Use:    "req <OSPA file>",
	Short:  "Send an OpenSPA request packet",
	Run:    reqCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

func ReqCmdSetup(c *cobra.Command) {
	c.Flags().Bool("auto-mode", false, "Automatically send request packet when the duration from the previous request is nearing 50% before termination")
	c.Flags().IP("client-ip", nil, "Client IP (v4 or v6) that will be requested for access to target (if empty, will be resolved)")
	c.Flags().String("target-protocol", lib.ProtocolTCP.Protocol, fmt.Sprintf("Target protocol you wish to access (%s)", internetProtocolSupportedHelpString()))
	c.Flags().IPP("target-ip", "t", nil, "Target IP (v4 or v6) that you wish to access (if empty, will use server's IP)")
	c.Flags().Uint16P("target-port-start", "p", 22, "Target (start) port that you wish to access")
	c.Flags().Uint16("target-port-end", 0, "Along with --target-port-start range of target ports that you wish to access")
	c.Flags().Uint("retry-count", 3, "")
	c.Flags().Uint("timeout", 3, "Timeout to wait for response in seconds")

	c.Flags().String("ipv4-resolver-server", internal.IPv4ServerDefault,
		"The server to use to resolve client's public IPv4 address (needs to be a URL)")
	c.Flags().String("ipv6-resolver-server", internal.IPv6ServerDefault,
		"The server to use to resolve client's public IPv6 address (needs to be a URL)")
}

func reqCmdRunFn(cmd *cobra.Command, args []string) {
	if len(args) < 1 {
		log.Fatal().Msg("Missing OSPA filepath argument")
	}

	ospaFilePath := args[0]
	reqHandle(cmd, ospaFilePath)
}

func reqHandle(cmd *cobra.Command, ospaFilePath string) {
	ospa, err := internal.OSPAFromFile(ospaFilePath)
	if err != nil {
		log.Fatal().Msgf("Failed to read OSPA file error: %s", err.Error())
	}

	log.Info().Msgf("Resolving server host: %s", ospa.ServerHost)
	serverIPAddr, err := net.ResolveIPAddr("ip", ospa.ServerHost)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to resolve server host: %s", ospa.ServerHost)
	}

	if serverIPAddr == nil || serverIPAddr.IP == nil {
		log.Fatal().Msgf("Server host: %s resolved with no IP", ospa.ServerHost)
	}

	serverIP := serverIPAddr.IP

	autoMode, err := cmd.Flags().GetBool("auto-mode")
	fatalOnErr(err, "auto-mode")

	tProto, err := cmd.Flags().GetString("target-protocol")
	fatalOnErr(err, "target-protocol")
	tProtocol, err := lib.InternetProtocolFromString(tProto)
	fatalOnErr(err, "Invalid internet protocol (ICMP,IPv4,TCP,UDP,ICMPv6")

	tIP, err := cmd.Flags().GetIP("target-ip")
	if err != nil {
		log.Info().Msgf("Target IP defaulting to server's IP: %s", serverIP)
		tIP = serverIP
	}

	tPortStart, err := cmd.Flags().GetUint16("target-port-start")
	fatalOnErr(err, "target-port-start")

	tPortEnd, err := cmd.Flags().GetUint16("target-port-end")
	fatalOnErr(err, "target-port-end")
	if tPortEnd == 0 {
		tPortEnd = tPortStart
	}

	clientIP, err := cmd.Flags().GetIP("client-ip")
	if err != nil {
		log.Info().Msgf("Client's IP will be determined by the use of public resolver")
		ip4, err := cmd.Flags().GetString("ipv4-resolver-server")
		if err != nil {
			log.Fatal().Err(err).Msgf("ipv4-resolver-server flag failed to get")
		}
		ip6, err := cmd.Flags().GetString("ipv6-resolver-server")
		if err != nil {
			log.Fatal().Err(err).Msgf("ipv6-resolver-server flag failed to get")
		}

		ip, err := internal.ResolveClientsIPAndVersionBasedOnTargetIP(ip4, ip6, tIP)
		if err != nil {
			log.Fatal().Err(err).Msgf("Failed to resolve client's IP")
		}
		log.Info().Msgf("Resolved client's IP: %s", ip.String())
		clientIP = ip
	}

	retryCount, err := cmd.Flags().GetUint("retry-count")
	fatalOnErr(err, "retryCount")

	timeoutSec, err := cmd.Flags().GetUint("timeout")
	fatalOnErr(err, "timeout")

	reqRoutineParam := internal.RequestRoutineParameters{
		ReqParams: internal.RequestRoutineReqParameters{
			ClientUUID:      ospa.ClientUUID,
			ServerIP:        serverIP,
			ServerPort:      ospa.ServerPort,
			TargetProto:     tProtocol,
			ClientIP:        clientIP,
			TargetIP:        tIP,
			TargetPortStart: int(tPortStart),
			TargetPortEnd:   int(tPortEnd),
		},
		AutoMode:   autoMode,
		RetryCount: int(retryCount),
		Timeout:    time.Duration(timeoutSec) * time.Second,
	}

	cs, err := internal.SetupClientCipherSuite(ospa)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to setup client cipher suite")
	}

	err = internal.RequestRoutine(reqRoutineParam, cs, internal.RequestRoutineOptDefault)
	if err != nil {
		log.Error().Err(err).Msgf("Request routine failed")
	}
}

func fatalOnErr(err error, str string) {
	if err != nil {
		log.Fatal().Msgf("%s error: %s", str, err.Error())
	}
}

func internetProtocolSupportedHelpString() string {
	proto := ""
	for i, p := range lib.InternetProtocolNumberSupported() {
		l := len(lib.InternetProtocolNumberSupported())
		proto += p.Protocol
		if i != l-1 {
			proto += ","
		}
	}
	return proto
}
