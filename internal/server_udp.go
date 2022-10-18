package internal

import (
	"context"
	"net"
	"strconv"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const readRequestBufferSize = openspalib.MaxPDUSize

type Server struct {
	udpServer  *UDPServer
	httpServer *HTTPServer
	handler    UDPDatagramRequestHandler
	reqCoord   *RequestCoordinator
	frm        *FirewallRuleManager
	settings   ServerSettings
}

const NoRequestHandlersDefault = 100

type ServerSettings struct {
	UDPServerIP       net.IP
	UDPServerPort     int
	NoRequestHandlers int
	FW                Firewall
	CS                crypto.CipherSuite
	Authz             AuthorizationStrategy

	// HTTP server parameters, if HTTPServerPort is 0, the HTTP server will not be started
	HTTPServerIP   net.IP
	HTTPServerPort int

	// Optional
	ADKSecret string
}

func NewServer(set ServerSettings) *Server {
	frm := NewFirewallRuleManager(set.FW)

	h := NewServerHandler(frm, set.CS, set.Authz, ServerHandlerOpt{ADKSecret: set.ADKSecret})
	var handler UDPDatagramRequestHandler
	var rc *RequestCoordinator
	if set.NoRequestHandlers > 0 {
		rc = NewRequestCoordinator(h, set.NoRequestHandlers)
		handler = rc
	} else {
		handler = &datagramRequestHandlerUnbound{h}
	}

	var httpServer *HTTPServer
	if set.HTTPServerPort != 0 {
		httpServer = NewHTTPServer(set.HTTPServerIP, set.HTTPServerPort)
	}

	s := &Server{
		udpServer:  NewUDPServer(set.UDPServerIP, set.UDPServerPort, handler),
		httpServer: httpServer,
		handler:    handler,
		reqCoord:   rc,
		settings:   set,
		frm:        frm,
	}
	return s
}

func (s *Server) Start() error {
	if err := s.frm.fw.FirewallSetup(); err != nil {
		log.Fatal().Err(err).Msgf("Failed to setup firewall")
	}

	if err := s.frm.Start(); err != nil {
		log.Fatal().Err(err).Msgf("Failed to start firewall rule manager")
	}

	if s.httpServer != nil {
		go func() {
			if err := s.httpServer.Start(); err != nil {
				log.Fatal().Err(err).Msgf("HTTP server crashed")
			}
		}()
	}

	bind := net.JoinHostPort(s.settings.UDPServerIP.String(), strconv.Itoa(s.settings.UDPServerPort))
	rc := s.reqCoord != nil // do we have a request coordinator?
	log.Info().Msgf("Starting UDP server (ADK support: %t, request coordinator: %t): %s", s.handler.ADKSupport(), rc, bind)
	if s.reqCoord != nil {
		s.reqCoord.Start()
	}

	return s.udpServer.Start()
}

func (s *Server) Stop() error {
	// s.reqCoord.Stop() // TODO

	if s.httpServer != nil {
		if err := s.httpServer.Stop(); err != nil {
			log.Error().Err(err).Msgf("Failed to stop HTTP server")
		}
	}

	if err := s.udpServer.Stop(); err != nil {
		return errors.Wrap(err, "udp server stop")
	}

	if err := s.frm.Stop(); err != nil {
		return errors.Wrap(err, "firewall rule manager stop")
	}

	return nil
}

type UDPServer struct {
	IP      net.IP
	Port    int
	handler UDPDatagramRequestHandler

	c *net.UDPConn

	metrics udpServerMetrics
}

type udpServerMetrics struct {
	datagramRX observability.Counter
	datagramTX observability.Counter
}

func NewUDPServer(ip net.IP, port int, reqHandle UDPDatagramRequestHandler) *UDPServer {
	u := &UDPServer{
		IP:      ip,
		Port:    port,
		handler: reqHandle,
		metrics: newUDPServerMetrics(),
	}
	return u
}

func (u *UDPServer) Start() error {
	return u.start()
}

func (u *UDPServer) start() error {
	lAddr := &net.UDPAddr{
		IP:   u.IP,
		Port: u.Port,
	}

	c, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		return errors.Wrap(err, "listen packet stopped")
	}

	u.c = c
	responder := NewUDPResponse(c, u.metrics)

	defer c.Close()

	b := make([]byte, readRequestBufferSize)
	for {
		n, rAddr, err := c.ReadFromUDP(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}

			return errors.Wrap(err, "failed to read from udp con")
		}

		u.metrics.datagramRX.Inc()

		bCpy := make([]byte, n)
		copy(bCpy, b)

		ctx := context.Background()
		u.handler.DatagramRequestHandler(ctx, responder, DatagramRequest{
			data:  bCpy,
			rAddr: *rAddr,
		})
	}

	return nil
}

func (u *UDPServer) Stop() error {
	return u.stop()
}

func (u *UDPServer) stop() error {
	if u.c != nil {
		if err := u.c.Close(); err != nil {
			return err
		}
	}

	return nil
}

func newUDPServerMetrics() udpServerMetrics {
	m := udpServerMetrics{}
	mr := getMetricsRepository()
	lbl := observability.NewLabels()

	m.datagramRX = mr.Count("udp_server_rx", lbl)
	m.datagramTX = mr.Count("udp_server_tx", lbl)
	return m
}

type DatagramRequest struct {
	data  []byte
	rAddr net.UDPAddr
}

type UDPDatagramRequestHandler interface {
	DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest)
	ADKSupport() bool
}

var _ UDPDatagramRequestHandler = &RequestCoordinator{}

type RequestCoordinator struct {
	reqHandler UDPDatagramRequestHandler
	queue      chan QueuedDatagramRequest

	noHandlers int
	started    bool
}

type QueuedDatagramRequest struct {
	DatagramRequest
	resp UDPResponser
	ctx  context.Context
}

func NewRequestCoordinator(h UDPDatagramRequestHandler, handlers int) *RequestCoordinator {
	d := &RequestCoordinator{
		reqHandler: h,
		queue:      make(chan QueuedDatagramRequest),
		noHandlers: handlers,
		started:    false,
	}
	return d
}

func (d *RequestCoordinator) Start() {
	if !d.started {
		d.startHandlers(d.queue, d.noHandlers)
	}
}

func (d *RequestCoordinator) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	d.queue <- QueuedDatagramRequest{ctx: ctx, DatagramRequest: r, resp: resp}
}

func (d *RequestCoordinator) ADKSupport() bool {
	return d.reqHandler.ADKSupport()
}

// startHandlers spawns size handler(), each in a goroutine.
func (d *RequestCoordinator) startHandlers(queue chan QueuedDatagramRequest, size int) {
	for i := 0; i < size; i++ {
		go d.handler(queue)
	}
}

func (d *RequestCoordinator) handler(queue chan QueuedDatagramRequest) {
	for r := range queue {
		if d.reqHandler != nil {
			d.reqHandler.DatagramRequestHandler(r.ctx, r.resp, r.DatagramRequest)
		}
	}
}

// datagramRequestHandlerUnbound spawns each DatagramRequestHandler in its own goroutine. This is dangerous
// since we spawn goroutines without any limit.
type datagramRequestHandlerUnbound struct {
	UDPDatagramRequestHandler
}

//nolint:lll
func (d *datagramRequestHandlerUnbound) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	go d.UDPDatagramRequestHandler.DatagramRequestHandler(ctx, resp, r)
}
