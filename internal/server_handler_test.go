package internal

import (
	"context"
	"net"
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestServerHandler_DatagramRequestHandler(t *testing.T) {
	fw := &FirewallStub{}
	cs := crypto.NewCipherSuiteStub()

	sh := NewServerHandler(fw, cs)

	reqData := openspalib.RequestData{
		TransactionId:   23,
		ClientUUID:      "09896692-c299-4f90-9906-2e23cfcc417c",
		ClientIP:        net.IPv4(88, 200, 23, 23),
		TargetProtocol:  openspalib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 80,
		TargetPortEnd:   80,
	}

	req, err := openspalib.NewRequest(reqData, cs)
	require.NoError(t, err)

	reqB, err := req.Marshal()
	require.NoError(t, err)

	resp := &UDPResponseMock{}
	resp.On("SendUDPResponse", net.UDPAddr{
		IP:   net.IPv4(88, 200, 23, 12),
		Port: 40975,
	}, mock.Anything).Return(nil).Once()

	sh.DatagramRequestHandler(context.TODO(), resp, DatagramRequest{
		data: reqB,
		rAddr: net.UDPAddr{
			IP:   net.IPv4(88, 200, 23, 12),
			Port: 40975,
		},
	})

	resp.AssertExpectations(t)
}
