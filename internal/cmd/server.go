package cmd

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/greenstatic/openspa/internal"
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

	server(cmd, sc)
}

func server(_ *cobra.Command, config internal.ServerConfig) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	cs, err := internal.NewServerCipherSuite(config.Crypto)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to setup server cipher suite")
	}

	s := internal.NewServer(internal.ServerSettings{
		IP:                net.ParseIP(config.Server.IP),
		Port:              config.Server.Port,
		NoRequestHandlers: internal.NoRequestHandlersDefault,
		FW:                nil, // TODO
		CS:                cs,
	})

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
	log.Info().Msgf("Stopping server")
	if err := s.Stop(); err != nil {
		log.Error().Err(err).Msgf("Server stop")
	}
	log.Info().Msgf("Successfully stopped server")
}
