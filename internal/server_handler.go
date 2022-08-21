package internal

import (
	"context"
	"net"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var _ UDPDatagramRequestHandler = &ServerHandler{}

type ServerHandler struct {
	// TODO
	cs crypto.CipherSuite
	fw Firewall
}

func NewServerHandler() *ServerHandler {
	o := &ServerHandler{}
	return o
}

func (o *ServerHandler) DatagramRequestHandler(_ context.Context, resp UDPResponser, r DatagramRequest) {
	log.Debug().Msgf("Received UDP datagram from: %s", r.rAddr.String())

	request, err := openspalib.RequestUnmarshal(r.data, o.cs)
	if err != nil {
		log.Info().Err(err).Msgf("OpenSPA request unmarshal failure")
		return
	}

	// TODO

	rd := openspalib.ResponseData{
		TransactionId:   request.Header.TransactionId,
		TargetProtocol:  openspalib.InternetProtocolNumber{},
		TargetIP:        nil,
		TargetPortStart: 0,
		TargetPortEnd:   0,
		Duration:        0,
	}

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
