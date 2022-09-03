package internal

import (
	"context"
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

var _ UDPDatagramRequestHandler = &ServerHandler{}

type ServerHandler struct {
	frm *FirewallRuleManager
	cs  crypto.CipherSuite

	authz AuthorizationStrategy
}

func NewServerHandler(frm *FirewallRuleManager, cs crypto.CipherSuite, authz AuthorizationStrategy) *ServerHandler {
	o := &ServerHandler{
		cs:    cs,
		frm:   frm,
		authz: authz,
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

	// Authentication has been performed as part of CipherSuite
	dur, err := o.authz.RequestAuthorization(request.Body)
	if err != nil {
		log.Info().Err(err).Msgf("OpenSPA request not authorized")
		return
	}

	fwRules, fwReq, err := firewallRuleFromRequestContainer(request.Body)
	if err != nil {
		log.Info().Err(err).Msgf("Failed to get firewall rule information from OpenSPA request")
		return
	}

	for _, r := range fwRules {
		if err := o.frm.Add(r, dur); err != nil {
			log.Error().Err(err).Msgf("Failed to add firewall rule: %s", r.String())
			return
		}
	}

	rd := openspalib.ResponseData{
		TransactionID:   request.Header.TransactionID,
		TargetProtocol:  fwReq.Proto,
		TargetIP:        fwReq.DstIP,
		TargetPortStart: fwReq.DstPortStart,
		TargetPortEnd:   fwReq.DstPortEnd,
		Duration:        dur,
		ClientUUID:      fwReq.ClientUUID,
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

type AuthorizationStrategy interface {
	RequestAuthorization(request tlv.Container) (time.Duration, error)
}

var _ AuthorizationStrategy = AuthorizationStrategyAllow{}

// AuthorizationStrategyAllow authorized any form of request as long as it is authenticated successfully (authentication
// should be performed externally).
type AuthorizationStrategyAllow struct {
	dur time.Duration
}

func NewAuthorizationStrategyAllow(duration time.Duration) *AuthorizationStrategyAllow {
	a := &AuthorizationStrategyAllow{
		dur: duration,
	}
	return a
}

func (a AuthorizationStrategyAllow) RequestAuthorization(_ tlv.Container) (time.Duration, error) {
	return a.dur, nil
}

type firewallRequest struct {
	ClientUUID   string
	Proto        openspalib.InternetProtocolNumber
	SrcIP        net.IP
	DstIP        net.IP
	DstPortStart int
	DstPortEnd   int
}

func firewallRuleFromRequestContainer(c tlv.Container) ([]FirewallRule, firewallRequest, error) {
	uuid, err := openspalib.ClientUUIDFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "client uuid")
	}

	p, err := openspalib.TargetProtocolFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "target protocol")
	}

	cIP, err := openspalib.ClientIPFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "client ip")
	}

	tIP, err := openspalib.TargetIPFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "target ip")
	}

	portStart, err := openspalib.TargetPortStartFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "target port start")
	}

	portEnd, err := openspalib.TargetPortEndFromContainer(c)
	if err != nil {
		return nil, firewallRequest{}, errors.Wrap(err, "target port end")
	}

	noPorts := portEnd - portStart + 1
	if noPorts < 0 {
		return nil, firewallRequest{}, errors.New("invalid target port range")
	}

	rules := make([]FirewallRule, 0, noPorts)

	for i := portStart; i <= portEnd; i++ {
		rules = append(rules, FirewallRule{
			Proto:   p.String(),
			SrcIP:   cIP,
			DstIP:   tIP,
			DstPort: i,
		})
	}

	return rules, firewallRequest{
		ClientUUID:   uuid,
		Proto:        p,
		SrcIP:        cIP,
		DstIP:        tIP,
		DstPortStart: portStart,
		DstPortEnd:   portEnd,
	}, nil
}
