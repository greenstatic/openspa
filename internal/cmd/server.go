package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/greenstatic/openspa/internal"
	"github.com/greenstatic/openspa/internal/xdp"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var ServerCmd = &cobra.Command{
	Use:    "server",
	Short:  "Start OpenSPA server",
	Run:    serverCmdRunFn,
	PreRun: PreRunLogSetupFn,
}

func ServerCmdSetup(c *cobra.Command) {
	c.Flags().StringP("config", "c", "config.yaml", "Server configuration file")
}

func serverCmdRunFn(cmd *cobra.Command, args []string) {
	configFilePath, err := cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to get config file path")
	}

	cBytes, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to read config file")
	}

	sc, err := internal.ServerConfigParse(cBytes)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to parse config file")
	}

	if err := sc.Verify(); err != nil {
		log.Fatal().Err(err).Msgf("Server config file invalid")
	}

	server(cmd, sc)
}

func server(_ *cobra.Command, config internal.ServerConfig) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	xdkMetricsStop := make(chan bool)
	xadk, err := xdpSetup(config, xdkMetricsStop)
	if err != nil {
		log.Fatal().Err(err).Msgf("ADK/XDP setup error")
	}

	cs, err := internal.NewServerCipherSuite(config.Crypto)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to setup server cipher suite")
	}

	fw, err := internal.NewFirewallFromServerConfigFirewall(config.Firewall)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to initialize firewall backend")
	}

	authz, err := internal.NewAuthorizationStrategyFromServerConfigAuthorization(config.Authorization)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to initialize authorization backend")
	}

	httpIP, httpPort := serverHTTPServerSettingsFromConfig(config)

	s := internal.NewServer(internal.ServerSettings{
		UDPServerIP:       net.ParseIP(config.Server.IP),
		UDPServerPort:     config.Server.Port,
		NoRequestHandlers: config.Server.RequestHandlers,
		FW:                fw,
		CS:                cs,
		Authz:             authz,
		ADKSecret:         config.Server.ADK.Secret,
		HTTPServerIP:      httpIP,
		HTTPServerPort:    httpPort,
	})

	if xadk != nil {
		if err := xadk.Start(); err != nil {
			log.Fatal().Err(err).Msgf("XDP/ADK start error")
		}
	}

	go func() {
		sig := <-sigs
		log.Info().Msgf("Received signal %s", sig.String())
		done <- true
	}()

	go func() {
		if err := s.Start(); err != nil {
			log.Fatal().Err(err).Msgf("Server error")
		}
	}()

	<-done

	if xadk != nil {
		log.Info().Msgf("Stopping XDP/ADK")
		if err := xadk.Stop(); err != nil {
			log.Error().Err(err).Msgf("Failed to stop XDP/ADK")
		}
		xdkMetricsStop <- true
	}

	log.Info().Msgf("Stopping server")
	if err := s.Stop(); err != nil {
		log.Error().Err(err).Msgf("Server stop")
	}
	log.Info().Msgf("Successfully stopped server")
}

func serverHTTPServerSettingsFromConfig(config internal.ServerConfig) (net.IP, int) {
	port := config.Server.HTTP.Port
	if !config.Server.HTTP.Enable {
		port = 0
	}

	return net.ParseIP(config.Server.HTTP.IP), port
}

func xdpADKEnabled(config internal.ServerConfig) bool {
	return config.Server.ADK.XDP.Mode == ""
}

func xdpPrecheck(config internal.ServerConfig) error {
	if !xdpADKEnabled(config) {
		return nil
	}

	if !xdp.IsSupported() {
		return errors.New("xdp is not supported in this build")
	}

	return nil
}

func xdpSetup(config internal.ServerConfig, metricsStop chan bool) (xdp.ADK, error) {
	if err := xdpPrecheck(config); err != nil {
		return nil, errors.Wrap(err, "xdp precheck")
	}

	if !xdpADKEnabled(config) {
		return nil, nil
	}

	xdpConf := config.Server.ADK.XDP
	mode, ok := xdp.ModeFromString(xdpConf.Mode)
	if !ok {
		return nil, errors.New("unsupported mode")
	}

	iName := xdpConf.Interfaces[0] // currently we only support a single interface

	set := xdp.ADKSettings{
		InterfaceName:   iName,
		Mode:            mode,
		ReplaceIfLoaded: true,
		UDPServerPort:   config.Server.Port,
	}

	adk, err := xdp.NewADK(set, internal.NewADKProofGen(config.Server.ADK.Secret))
	if err != nil {
		return nil, errors.Wrap(err, "new adk")
	}

	internal.SetupXDPADKMetrics(adk, metricsStop)

	return adk, nil
}
