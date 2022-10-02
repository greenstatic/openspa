package internal

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/greenstatic/openspa/internal/observability/metrics"
	"github.com/rs/zerolog/log"
)

const ServerHTTPPortDefault = 22212

type HTTPServer struct {
	bindIP   net.IP
	bindPort int

	server *http.Server
	prom   *metrics.PrometheusRepository
}

func NewHTTPServer(ip net.IP, port int) *HTTPServer {
	h := &HTTPServer{
		bindIP:   ip,
		bindPort: port,
	}

	return h
}

func (h *HTTPServer) Start() error {
	return h.start()
}

func (h *HTTPServer) start() error {
	h.prom = prometheusRepo

	mux := http.NewServeMux()
	h.setHandles(mux)

	h.server = &http.Server{
		Handler:      mux,
		Addr:         net.JoinHostPort(h.bindIP.String(), strconv.Itoa(h.bindPort)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Info().Msgf("Starting HTTP server on: %s", h.server.Addr)
	if err := h.server.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			log.Info().Msgf("HTTP server closed")
		} else {
			return err
		}
	}

	return nil
}

func (h *HTTPServer) Stop() error {
	return h.stop()
}

func (h *HTTPServer) stop() error {
	if h.server == nil {
		return nil
	}

	log.Debug().Msgf("Stopping HTTP server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return h.server.Shutdown(ctx)
}

func (h *HTTPServer) setHandles(m *http.ServeMux) {
	m.HandleFunc("/", handleEndpointRoot)
	if h.prom != nil {
		m.Handle("/metrics", h.prom.Handler())
	}
}

func handleEndpointRoot(w http.ResponseWriter, r *http.Request) {
	setHTTPResponseHeaders(w)

	if r.URL.Path != "/" {
		handleStatusNotFound(w, r)
		return
	}

	panicOnErr(json.NewEncoder(w).Encode(struct {
		Msg     string `json:"msg"`
		Version string `json:"version"`
	}{
		Msg:     "OpenSPA Server",
		Version: Version(),
	}))
}

func handleStatusNotFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	panicOnErr(json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{
		Error: "not found",
	}))
}

func setHTTPResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
