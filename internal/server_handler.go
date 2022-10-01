package internal

import (
	"context"
	"net"

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

	adkProver *openspalib.ADKProver
}

type ServerHandlerOpt struct {
	ADKSecret string
}

func NewServerHandler(frm *FirewallRuleManager, cs crypto.CipherSuite, authz AuthorizationStrategy,
	opt ServerHandlerOpt) *ServerHandler {
	o := &ServerHandler{
		cs:    cs,
		frm:   frm,
		authz: authz,
	}

	if len(opt.ADKSecret) != 0 {
		p, err := openspalib.NewADKProver(opt.ADKSecret)
		if err != nil {
			panic(err)
		}

		o.adkProver = &p
	}

	return o
}

func (o *ServerHandler) DatagramRequestHandler(_ context.Context, resp UDPResponser, r DatagramRequest) {
	remote := r.rAddr.String()
	log.Debug().Msgf("Received UDP datagram from: %s", remote)

	if o.adkProver != nil {
		header, err := openspalib.RequestUnmarshalHeader(r.data)
		if err != nil {
			log.Info().Err(err).Msgf("OpenSPA request unmarshal header failure for: %s", remote)
			return
		}

		if header.ADKProof == 0 {
			log.Debug().Msgf("OpenSPA request missing ADK proof for: %s", remote)
			return
		}

		if err := o.adkProver.Valid(header.ADKProof); err != nil {
			log.Debug().Msgf("OpenSPA request ADK proof rejected for: %s", remote)
			return
		}

		log.Debug().Msgf("OpenSPA request ADK proof accepted for: %s", remote)
	}

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

	fwRule, fwReq, err := firewallRuleFromRequestContainer(request.Body)
	if err != nil {
		log.Info().Err(err).Msgf("Failed to get firewall rule information from OpenSPA request")
		return
	}

	clientUUID, err := openspalib.ClientUUIDFromContainer(request.Body)
	if err != nil {
		log.Info().Err(err).Msgf("Failed to get client uuid from OpenSPA request")
		return
	}

	meta := FirewallRuleMetadata{
		ClientUUID: clientUUID,
		Duration:   dur,
	}

	if err := o.frm.Add(fwRule, meta); err != nil {
		log.Error().Err(err).Msgf("Failed to add firewall rule: %s", fwRule.String())
		return
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

func (o *ServerHandler) ADKSupport() bool {
	return o.adkProver != nil
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

type firewallRequest struct {
	ClientUUID   string
	Proto        openspalib.InternetProtocolNumber
	SrcIP        net.IP
	DstIP        net.IP
	DstPortStart int
	DstPortEnd   int
}

func firewallRuleFromRequestContainer(c tlv.Container) (FirewallRule, firewallRequest, error) {
	uuid, err := openspalib.ClientUUIDFromContainer(c)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "client uuid")
	}

	firewallC, err := openspalib.TLVFromContainer(c, openspalib.FirewallKey)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "firewall tlv container")
	}
	if firewallC == nil {
		return FirewallRule{}, firewallRequest{}, errors.New("firewall tlv container is nil")
	}

	p, err := openspalib.TargetProtocolFromContainer(firewallC)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "target protocol")
	}

	cIP, err := openspalib.ClientIPFromContainer(firewallC)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "client ip")
	}

	tIP, err := openspalib.TargetIPFromContainer(firewallC)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "target ip")
	}

	portStart, err := openspalib.TargetPortStartFromContainer(firewallC)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "target port start")
	}

	portEnd, err := openspalib.TargetPortEndFromContainer(firewallC)
	if err != nil {
		return FirewallRule{}, firewallRequest{}, errors.Wrap(err, "target port end")
	}

	noPorts := portEnd - portStart + 1
	if noPorts < 0 {
		return FirewallRule{}, firewallRequest{}, errors.New("invalid target port range")
	}

	rule := FirewallRule{
		Proto:        p.String(),
		SrcIP:        cIP,
		DstIP:        tIP,
		DstPortStart: portStart,
		DstPortEnd:   portEnd,
	}

	return rule, firewallRequest{
		ClientUUID:   uuid,
		Proto:        p,
		SrcIP:        cIP,
		DstIP:        tIP,
		DstPortStart: portStart,
		DstPortEnd:   portEnd,
	}, nil
}
