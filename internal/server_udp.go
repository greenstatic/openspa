package internal

import (
	"context"
	"net"
	"strconv"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const readRequestBufferSize = openspalib.MaxPDUSize

type Server struct {
	udpServer *UDPServer
	reqCoord  *RequestCoordinator
	settings  ServerSettings
}

const NoRequestHandlersDefault = 100

type ServerSettings struct {
	IP                net.IP
	Port              int
	NoRequestHandlers int
	FW                Firewall
	CS                crypto.CipherSuite
	Authz             AuthorizationStrategy
}

func NewServer(set ServerSettings) *Server {
	h := NewServerHandler(NewFirewallRuleManager(set.FW), set.CS, set.Authz)
	rc := NewRequestCoordinator(h, set.NoRequestHandlers)

	udpServer := NewUDPServer(set.IP, set.Port, rc)

	s := &Server{
		udpServer: udpServer,
		reqCoord:  rc,
		settings:  set,
	}
	return s
}

func (s *Server) Start() error {
	bind := net.JoinHostPort(s.settings.IP.String(), strconv.Itoa(s.settings.Port))
	log.Info().Msgf("Starting UDP server: %s", bind)
	s.reqCoord.Start()

	return s.udpServer.Start()
}

func (s *Server) Stop() error {
	// s.reqCoord.Stop() // TODO

	return s.udpServer.Stop()
}

type UDPServer struct {
	IP      net.IP
	Port    int
	handler UDPDatagramRequestHandler

	c *net.UDPConn
}

func NewUDPServer(ip net.IP, port int, reqHandle UDPDatagramRequestHandler) *UDPServer {
	u := &UDPServer{
		IP:      ip,
		Port:    port,
		handler: reqHandle,
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
	responder := NewUDPResponse(c)

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

type DatagramRequest struct {
	data  []byte
	rAddr net.UDPAddr
}

type UDPDatagramRequestHandler interface {
	DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest)
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
