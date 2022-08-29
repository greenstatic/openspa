package internal

import (
	"context"
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var _ UDPDatagramRequestHandler = &ServerHandler{}

type ServerHandler struct {
	fw Firewall
	cs crypto.CipherSuite
}

func NewServerHandler(fw Firewall, cs crypto.CipherSuite) *ServerHandler {
	o := &ServerHandler{
		cs: cs,
		fw: fw,
	}
	return o
}

func (o *ServerHandler) DatagramRequestHandler(_ context.Context, resp UDPResponser, r DatagramRequest) {
	log.Debug().Msgf("Received UDP datagram from: %s", r.rAddr.String())

	request, err := openspalib.RequestUnmarshal(r.data, o.cs)
	if err != nil {
		log.Info().Err(err).Msgf("OpenSPA request unmarshal failure")
		return
	}

	// TODO - Start: replace this with proper business logic
	tIP, err := openspalib.TargetIPFromContainer(request.Body)
	if err != nil {
		return
	}

	tPortStart, err := openspalib.TargetPortStartFromContainer(request.Body)
	if err != nil {
		return
	}

	tPortEnd, err := openspalib.TargetPortEndFromContainer(request.Body)
	if err != nil {
		return
	}

	rd := openspalib.ResponseData{
		TransactionID:   request.Header.TransactionID,
		TargetProtocol:  openspalib.InternetProtocolNumber{},
		TargetIP:        tIP,
		TargetPortStart: tPortStart,
		TargetPortEnd:   tPortEnd,
		Duration:        time.Hour,
	}
	// TODO - End

	response, err := openspalib.NewResponse(rd, o.cs)
	if err != nil {
		log.Warn().Err(err).Msgf("Failed to create OpenSPA response")
		return
	}

	responseB, err := response.Marshal()
	if err != nil {
		log.Warn().Err(err).Msgf("Failed to marshal OpenSPA response")
		return
	}

	err = resp.SendUDPResponse(r.rAddr, responseB)
	if err != nil {
		log.Warn().Err(err).Msgf("Failed to send OpenSPA response")
	}
}

type UDPResponser interface {
	SendUDPResponse(dst net.UDPAddr, body []byte) error
}

type UDPResponse struct {
	c *net.UDPConn
}

func NewUDPResponse(c *net.UDPConn) *UDPResponse {
	r := &UDPResponse{
		c: c,
	}
	return r
}

func (u *UDPResponse) SendUDPResponse(dst net.UDPAddr, body []byte) error {
	if u.c == nil {
		return errors.New("no udp conn")
	}

	_, err := u.c.WriteTo(body, &dst)
	if err != nil {
		return errors.Wrap(err, "udp write")
	}

	return nil
}
