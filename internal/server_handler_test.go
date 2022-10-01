package internal

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

//nolint:dupl
func TestServerHandler_DatagramRequestHandler(t *testing.T) {
	fw := &FirewallMock{}
	frm := NewFirewallRuleManager(fw)
	cs := crypto.NewCipherSuiteStub()
	adkSecret := "7O4ZIRI"

	sh := NewServerHandler(frm, cs, NewAuthorizationStrategyAllow(time.Hour), ServerHandlerOpt{ADKSecret: adkSecret})

	reqData := openspalib.RequestData{
		TransactionID:   23,
		ClientUUID:      "09896692-c299-4f90-9906-2e23cfcc417c",
		ClientIP:        net.IPv4(88, 200, 23, 23),
		TargetProtocol:  openspalib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 80,
		TargetPortEnd:   80,
	}

	req, err := openspalib.NewRequest(reqData, cs, openspalib.RequestDataOpt{ADKSecret: adkSecret})
	require.NoError(t, err)

	reqB, err := req.Marshal()
	require.NoError(t, err)

	resp := &UDPResponseMock{}
	resp.On("SendUDPResponse", net.UDPAddr{
		IP:   net.IPv4(88, 200, 23, 12),
		Port: 40975,
	}, mock.Anything).Return(nil).Once()
	fw.On("RuleAdd", FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(88, 200, 23, 23).To4(),
		DstIP:        net.IPv4(88, 200, 23, 19).To4(),
		DstPortStart: 80,
		DstPortEnd:   80,
	}, mock.Anything).Return(nil).Once()

	sh.DatagramRequestHandler(context.TODO(), resp, DatagramRequest{
		data: reqB,
		rAddr: net.UDPAddr{
			IP:   net.IPv4(88, 200, 23, 12),
			Port: 40975,
		},
	})

	resp.AssertExpectations(t)
	fw.AssertExpectations(t)
}

//nolint:dupl
func TestServerHandler_DatagramRequestHandler_WithoutADKProof(t *testing.T) {
	fw := &FirewallMock{}
	frm := NewFirewallRuleManager(fw)
	cs := crypto.NewCipherSuiteStub()
	adkSecret := ""

	sh := NewServerHandler(frm, cs, NewAuthorizationStrategyAllow(time.Hour), ServerHandlerOpt{ADKSecret: adkSecret})

	reqData := openspalib.RequestData{
		TransactionID:   23,
		ClientUUID:      "09896692-c299-4f90-9906-2e23cfcc417c",
		ClientIP:        net.IPv4(88, 200, 23, 23),
		TargetProtocol:  openspalib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 80,
		TargetPortEnd:   80,
	}

	req, err := openspalib.NewRequest(reqData, cs, openspalib.RequestDataOpt{ADKSecret: adkSecret})
	require.NoError(t, err)

	reqB, err := req.Marshal()
	require.NoError(t, err)

	resp := &UDPResponseMock{}
	resp.On("SendUDPResponse", net.UDPAddr{
		IP:   net.IPv4(88, 200, 23, 12),
		Port: 40975,
	}, mock.Anything).Return(nil).Once()
	fw.On("RuleAdd", FirewallRule{
		Proto:        FirewallProtoTCP,
		SrcIP:        net.IPv4(88, 200, 23, 23).To4(),
		DstIP:        net.IPv4(88, 200, 23, 19).To4(),
		DstPortStart: 80,
		DstPortEnd:   80,
	}, mock.Anything).Return(nil).Once()

	sh.DatagramRequestHandler(context.TODO(), resp, DatagramRequest{
		data: reqB,
		rAddr: net.UDPAddr{
			IP:   net.IPv4(88, 200, 23, 12),
			Port: 40975,
		},
	})

	resp.AssertExpectations(t)
	fw.AssertExpectations(t)
}

func TestServerHandler_DatagramRequestHandler_InvalidADKProof(t *testing.T) {
	fw := &FirewallMock{}
	frm := NewFirewallRuleManager(fw)
	cs := crypto.NewCipherSuiteStub()

	sh := NewServerHandler(frm, cs, NewAuthorizationStrategyAllow(time.Hour), ServerHandlerOpt{ADKSecret: "7O4ZIRI"})

	reqData := openspalib.RequestData{
		TransactionID:   23,
		ClientUUID:      "09896692-c299-4f90-9906-2e23cfcc417c",
		ClientIP:        net.IPv4(88, 200, 23, 23),
		TargetProtocol:  openspalib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 80,
		TargetPortEnd:   80,
	}

	req, err := openspalib.NewRequest(reqData, cs, openspalib.RequestDataOpt{ADKSecret: "3HRZN3Y"})
	require.NoError(t, err)

	reqB, err := req.Marshal()
	require.NoError(t, err)

	resp := &UDPResponseMock{}

	sh.DatagramRequestHandler(context.TODO(), resp, DatagramRequest{
		data: reqB,
		rAddr: net.UDPAddr{
			IP:   net.IPv4(88, 200, 23, 12),
			Port: 40975,
		},
	})

	resp.AssertExpectations(t)
	fw.AssertExpectations(t)
}

func TestFirewallRuleFromRequestContainer(t *testing.T) {
	// TODO
}
