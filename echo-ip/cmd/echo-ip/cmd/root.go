package cmd

import (
	"fmt"
	"github.com/greenstatic/echo-ip/internal"
	"github.com/spf13/cobra"
	"net"
	"os"
)

const (
	Version = "1.2.0"
)

var (
	port        uint16
	bindIP      net.IP
	certificate string
	privateKey  string
)

var rootCmd = &cobra.Command{
	Use:   "echo-ip",
	Short: "Returns the client's public IP",
	Long:  `A small Go web service to return the client's public IP.`,
	Run: func(cmd *cobra.Command, args []string) {

		server := internal.Server{
			Version,
			port,
			bindIP.String(),
			certificate,
			privateKey,
		}

		server.StartServer()
	},
}

func init() {
	rootCmd.Flags().Uint16VarP(&port, "port", "p", 0, "Port to listen to")
	rootCmd.Flags().IPVarP(&bindIP, "bind", "b", net.IP{0, 0, 0, 0}, "Bind to IP")

	rootCmd.Flags().StringVarP(&certificate, "cert", "c", "", "Server's HTTPS certificate")
	rootCmd.Flags().StringVarP(&privateKey, "privKey", "k", "", "Server's certificate private key")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
