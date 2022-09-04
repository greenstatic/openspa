package internal

import (
	"net"
	"time"

	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
)

type udpSenderMock struct {
	mock.Mock
}

func (u *udpSenderMock) SendUDPRequest(req []byte, dest net.UDPAddr, timeout time.Duration) ([]byte, error) {
	args := u.Called(req, dest, timeout)
	return args.Get(0).([]byte), args.Error(1)
}

type udpSenderStubServer struct {
	responderParams stubServerResponderParams
	cs              crypto.CipherSuite
	preHook         func(req []byte, dest net.UDPAddr, timeout time.Duration)
}

func (u *udpSenderStubServer) SendUDPRequest(req []byte, dest net.UDPAddr, timeout time.Duration) ([]byte, error) {
	if u.preHook != nil {
		u.preHook(req, dest, timeout)
	}

	resp, err := stubServerResponder(req, u.cs, u.responderParams)
	if err != nil {
		return nil, errors.Wrap(err, "stub server responder")
	}

	respB, err := resp.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "response marshal")
	}

	return respB, nil
}

type stubServerResponderParams struct {
	Duration time.Duration
}

func stubServerResponder(reqB []byte, cs crypto.CipherSuite, params stubServerResponderParams) (*lib.Response, error) {
	req, err := lib.RequestUnmarshal(reqB, cs)
	if err != nil {
		return nil, errors.Wrap(err, "request unmarshal")
	}

	clientUUID, err := lib.ClientUUIDFromContainer(req.Body)
	if err != nil {
		return nil, errors.Wrap(err, "request has no client uuid")
	}

	firewallC, err := lib.TLVFromContainer(req.Body, lib.FirewallKey)
	if err != nil {
		return nil, errors.Wrap(err, "firewall tlv from container")
	}

	if firewallC == nil {
		return nil, errors.New("firewall tlv container nil")
	}

	targetProto, err := lib.TargetProtocolFromContainer(firewallC)
	if err != nil {
		return nil, errors.Wrap(err, "target protocol from container")
	}

	targetIP, err := lib.TargetIPFromContainer(firewallC)
	if err != nil {
		return nil, errors.Wrap(err, "target ip from container")
	}

	targetPortStart, err := lib.TargetPortStartFromContainer(firewallC)
	if err != nil {
		return nil, errors.Wrap(err, "target port start from container")
	}

	targetPortEnd, err := lib.TargetPortEndFromContainer(firewallC)
	if err != nil {
		return nil, errors.Wrap(err, "target port end from container")
	}

	resp, err := lib.NewResponse(lib.ResponseData{
		TransactionID:   req.Header.TransactionID,
		TargetProtocol:  targetProto,
		TargetIP:        targetIP,
		TargetPortStart: targetPortStart,
		TargetPortEnd:   targetPortEnd,
		Duration:        params.Duration,
		ClientUUID:      clientUUID,
	}, cs)
	if err != nil {
		return nil, errors.Wrap(err, "new response")
	}

	return resp, nil
}
