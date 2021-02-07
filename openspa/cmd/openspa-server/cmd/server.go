package cmd

import (
	"errors"
	"github.com/greenstatic/openspa/internal/extensionScripts"
	"github.com/greenstatic/openspa/internal/firewalltracker"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"github.com/greenstatic/openspa/internal/ospa"
	"github.com/greenstatic/openspa/internal/server"
	"github.com/greenstatic/openspalib/cryptography"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var (
	publicKeyGlobal  string
	privateKeyGlobal string

	portGlobal    uint16
	bindIPGlobal  net.IP
	cfgFileGlobal string

	serverIPGlobal       net.IP
	echoIPv4ServerGlobal string
	echoIPv6ServerGlobal string
)

var serverCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the OpenSPA server",
	Long:  `Starts the OpenSPA server`,
	Run: func(cmd *cobra.Command, args []string) {

		if err := startup(); err != nil {
			os.Exit(unexpectedError)
			return
		}

		// Open the private/public keys
		privKeyPath := viper.GetString("privateKey")
		log.WithField("path", privKeyPath).Debug("Using server private key")
		privKeyByte, err := cryptography.ReadPEMFile(privKeyPath)
		if err != nil {
			log.WithField("path", privKeyPath).Error("Failed to open server's private key")
			log.Error(err)
			os.Exit(failedToReadServerPrivateKey)
			return
		}

		pubKeyPath := viper.GetString("publicKey")
		log.WithField("path", privKeyPath).Debug("Using server public key")
		pubKeyByte, err := cryptography.ReadPEMFile(pubKeyPath)
		if err != nil {
			log.WithField("path", privKeyPath).Error("Failed to open server's public key")
			log.Error(err)
			os.Exit(failedToReadServerPublicKey)
			return
		}

		// Decode the private/public keys
		privKey, err := cryptography.DecodeX509PrivateKeyRSA(privKeyByte)
		if err != nil {
			log.Error("Failed to decode servers's private key")
			log.Error(err)
			os.Exit(failedToDecodeServerPrivateKey)
			return
		}

		pubKey, err := cryptography.DecodeX509PublicKeyRSA(pubKeyByte)
		if err != nil {
			log.Error("Failed to decode servers's public key")
			log.Error(err)
			os.Exit(failedToDecodeServerPublicKey)
			return
		}

		// Get ES
		es := extensionScripts.Scripts{
			viper.GetString("extensionscripts.userDirectoryService"),
			viper.GetString("extensionscripts.authorization"),
			viper.GetString("extensionscripts.ruleAdd"),
			viper.GetString("extensionscripts.ruleRemove"),
		}

		fwState := firewalltracker.Create(es.GetRuleAdd(), es.GetRuleRemove())
		replay := server.ReplayDetect{}
		replay.Setup()

		bindIp := net.ParseIP(viper.GetString("bind"))
		binPort := uint16(viper.GetInt("port"))

		server := server.New{
			bindIp,
			binPort,
			privKey,
			pubKey,
			es,
			fwState,
			&replay}

		log.WithFields(log.Fields{"bindIp": bindIp, "port": binPort}).Info("Starting server")

		// Signal handler to shutdown server
		sigs := make(chan os.Signal, 1)
		shutdown := make(chan bool, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go server.FirewallState.SignalReceiver(sigs, shutdown)

		// Run the server
		go func() {
			err = server.Receive()
			if err != nil {
				log.Fatal("Stopping server, due to unexpected error")
				log.Fatal(err)
				os.Exit(unexpectedError)
				return
			}
		}()

		<-shutdown
	},
}

// Initialize CLI flags
func init() {

	cobra.OnInitialize(initConfig)
	serverCmd.Flags().StringVarP(&cfgFileGlobal, "config", "c", "", "config file (default is ./config.yaml)")

	serverCmd.Flags().StringVar(&publicKeyGlobal, "public-key", "", "Server's public Key")
	serverCmd.Flags().StringVar(&privateKeyGlobal, "private-key", "", "Server's private Key")

	serverCmd.Flags().Uint16VarP(&portGlobal, "port", "p", ospa.DefaultServerPort, "Port to listen for OpenSPA request packets")
	serverCmd.Flags().IPVarP(&bindIPGlobal, "bind", "b", net.IP{0, 0, 0, 0}, "Bind to IP (IPv4/IPv6)")

	serverCmd.Flags().IPVar(&serverIPGlobal, "server-ip", net.IP{0, 0, 0, 0}, "The servers public IP (IPv4/IPv6)")

	serverCmd.Flags().StringVar(&echoIPv4ServerGlobal, "echo-ipv4-server", ipresolver.DefaultEchoIpV4Server,
		"The IPv4 Echo-IP server to use for public IP resolution (needs to be a URL)")

	serverCmd.Flags().StringVar(&echoIPv6ServerGlobal, "echo-ipv6-server", ipresolver.DefaultEchoIpV6Server,
		"The IPv6 Echo-IP server to use for public IP resolution (needs to be a URL)")

	viper.BindPFlag("publicKey", serverCmd.Flags().Lookup("public-key"))
	viper.BindPFlag("privateKey", serverCmd.Flags().Lookup("private-key"))

	viper.BindPFlag("port", serverCmd.Flags().Lookup("port"))
	viper.BindPFlag("bind", serverCmd.Flags().Lookup("bind"))
	viper.BindPFlag("serverIp", serverCmd.Flags().Lookup("server-ip"))
	viper.BindPFlag("echoIpv4Server", serverCmd.Flags().Lookup("echo-ipv4-server"))
	viper.BindPFlag("echoIpv6Server", serverCmd.Flags().Lookup("echo-ipv6-server"))

	rootCmd.AddCommand(serverCmd)
}

// Initialize the config reader
func initConfig() {
	viper.SetConfigType("yaml")

	if cfgFileGlobal != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFileGlobal)
		log.WithField("path", cfgFileGlobal).Debug("Using config file")
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		log.Debug("Searching for default config file in current working directory ./config.yaml")
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Error("Can't read config file")
		log.Error(err)
		os.Exit(failedToReadConfig)
	}
}

// Check if all the required fields are set either from the config
// file or using the command line flags.
func startup() error {

	bind := viper.GetString("bind")
	port := viper.GetInt("port")

	publicKey := viper.GetString("publicKey")
	if publicKey == "" {
		log.Error("publicKey field missing from config")
		return errors.New("publicKey value missing")
	}

	privateKey := viper.GetString("privateKey")
	if privateKey == "" {
		log.Error("privateKey field missing from config")
		return errors.New("privateKey value missing")
	}

	serverIP := viper.GetString("serverIp")

	if net.ParseIP(serverIP).String() == "" || serverIP == "0.0.0.0" || serverIP == "::" {

		// Use the Echo-IP IP version resolver depending on the bind address.
		echoIPResolver := viper.GetString("echoIPv4Server")
		if net.ParseIP(bind).To4() == nil {
			echoIPResolver = viper.GetString("echoIPv6Server")
		}

		log.WithField("echoIpServer", echoIPResolver).Debug("Automatically resolving IPs using Echo-IP")

		publicIP, _, err := ipresolver.EchoIPPublicResolver{}.GetPublicIP(echoIPResolver)
		if err != nil {
			log.WithField("echoIpServer", echoIPResolver).Error("Failed to resolve IPs using Echo-IP")
			os.Exit(unexpectedError)
			return errors.New("failed to resolve ips")
		}
		serverIP = publicIP.String()
		log.WithField("ip", publicIP).Info("Successfully resolved public IP")
	} else {
		log.WithField("ip", serverIP).Debug("Using provided server IP")
	}

	esUDS := viper.GetString("extensionscripts.userDirectoryService")
	if esUDS == "" {
		log.Error("Missing userDirectoryService field under extension scripts in config")
		return errors.New("userDirectoryService value missing")
	}

	esAuthorization := viper.GetString("extensionScripts.authorization")
	if esAuthorization == "" {
		log.Error("Missing authorization field under extension scripts in config")
		return errors.New("authorization value missing")
	}

	esRuleAdd := viper.GetString("extensionScripts.ruleAdd")
	if esRuleAdd == "" {
		log.Error("Missing ruleAdd field under extension scripts in config")
		return errors.New("ruleAdd value missing")
	}

	esRuleRemove := viper.GetString("extensionScripts.ruleRemove")
	if esRuleRemove == "" {
		log.Error("Missing ruleRemove field under extension scripts in config")
		return errors.New("ruleRemove value missing")
	}

	log.WithFields(log.Fields{
		"bind":                  bind,
		"port":                  port,
		"publicKey":             publicKey,
		"privateKey":            privateKey,
		"serverIp":              serverIP,
		"esUserDirectoryServer": esUDS,
		"esAuthorization":       esAuthorization,
		"esRuleAdd":             esRuleAdd,
		"esRuleRemove":          esRuleRemove,
	}).
		Debug("Config values are set")

	return nil
}
