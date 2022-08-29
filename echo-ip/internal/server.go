package internal

import (
	"fmt"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	httpPort  = 80
	httpsPort = 443
	timeout   = 5 // seconds
)

var version string

type Server struct {
	Version     string
	Port        uint16
	BindIP      string
	Certificate string
	PrivateKey  string
}

func (server *Server) StartServer() {
	version = server.Version

	r := mux.NewRouter()
	r.HandleFunc("/", ipHandler).Methods("GET", "POST")
	r.HandleFunc("/health", healthHandler).Methods("GET", "POST")

	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)
	http.Handle("/", r)

	loggedRouter := handlers.LoggingHandler(os.Stdout, r)

	https := false

	if server.Certificate != "" && server.PrivateKey != "" {
		https = true
	}

	port := int(server.Port)

	if port == 0 {
		if https {
			port = httpsPort
		} else {
			port = httpPort
		}
	}

	socket := net.JoinHostPort(server.BindIP, strconv.Itoa(port))

	srv := &http.Server{
		Handler:      loggedRouter,
		Addr:         socket,
		WriteTimeout: timeout * time.Second,
		ReadTimeout:  timeout * time.Second,
	}

	if https {
		// HTTPS
		fmt.Printf("Starting HTTPS server on: %s\n", socket)
		log.Fatal(srv.ListenAndServeTLS(server.Certificate, server.PrivateKey))
	} else {
		// HTTP
		fmt.Printf("Starting HTTP server on: %s\n", socket)
		log.Fatal(srv.ListenAndServe())
	}
}
