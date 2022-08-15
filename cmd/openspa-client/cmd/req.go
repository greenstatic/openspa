package cmd

import (
	"fmt"
	"time"

	"github.com/greenstatic/openspa/internal"
	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var reqCmd = &cobra.Command{
	Use:   "req <OSPA file>",
	Short: "Send an OpenSPA request packet",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatal().Msg("Missing OSPA filepath argument")
		}

		ospaFilePath := args[0]
		reqHandle(cmd, ospaFilePath)
	},
	PreRun: preRunLogSetupFun,
}

func reqCmdInit() {
	reqCmd.Flags().Bool("auto-mode", false, "Automatically send request packet when the duration from the previous request is nearing 50% before termination")
	reqCmd.Flags().IP("client-ip", nil, "Client IP (v4 or v6) that will be requested for access to target (if empty, will be resolved)")
	reqCmd.Flags().String("target-protocol", lib.ProtocolTCP.Protocol, fmt.Sprintf("Target protocol you wish to access (%s)", internetProtocolSupportedHelpString()))
	reqCmd.Flags().IPP("target-ip", "t", nil, "Target IP (v4 or v6) that you wish to access (if empty, will use server's IP)")
	reqCmd.Flags().Uint16P("target-port-start", "p", 22, "Target (start) port that you wish to access")
	reqCmd.Flags().Uint16("target-port-end", 0, "Along with --target-port-start range of target ports that you wish to access")
	reqCmd.Flags().Uint("retry-count", 3, "")
	reqCmd.Flags().Uint("timeout", 3, "Timeout to wait for response in seconds")
}

func reqHandle(cmd *cobra.Command, ospaFilePath string) {
	ospa, err := internal.OSPAFromFile(ospaFilePath)
	if err != nil {
		log.Fatal().Msgf("Failed to read OSPA file error: %s", err.Error())
	}

	autoMode, err := cmd.Flags().GetBool("auto-mode")
	fatalOnErr(err, "auto-mode")

	clientIP, err := cmd.Flags().GetIP("client-ip")
	if err != nil {
		log.Info().Msgf("Client's IP will be determined by the use of public resolver")
	}

	tProto, err := cmd.Flags().GetString("target-protocol")
	fatalOnErr(err, "target-protocol")
	tProtocol, err := lib.InternetProtocolFromString(tProto)
	fatalOnErr(err, "Invalid internet protocol (ICMP,IPv4,TCP,UDP,ICMPv6")

	tIP, err := cmd.Flags().GetIP("target-ip")
	if err != nil {
		log.Info().Msgf("Target IP defaulting to server's IP")
	}

	tPortStart, err := cmd.Flags().GetUint16("target-port-start")
	fatalOnErr(err, "target-port-start")

	tPortEnd, err := cmd.Flags().GetUint16("target-port-end")
	fatalOnErr(err, "target-port-end")
	if tPortEnd == 0 {
		tPortEnd = tPortStart
	}

	retryCount, err := cmd.Flags().GetUint("retry-count")
	fatalOnErr(err, "retryCount")

	timeoutSec, err := cmd.Flags().GetUint("timeout")
	fatalOnErr(err, "timeout")

	reqRoutineParam := internal.RequestRoutineParameters{
		OSPA: ospa,
		ReqParams: internal.RequestRoutineReqParameters{
			ClientUUID:      "",
			ServerHost:      ospa.ServerHost,
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

	cs := crypto.NewCipherSuiteStub() // TODO - implement

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
