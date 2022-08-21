package internal

import (
	"context"
	"net"
	"testing"
)

func TestServerHandler_DatagramRequestHandler(t *testing.T) {
	sh := NewServerHandler()

	// TODO - replace body payload with openspa req
	resp := &UDPResponseMock{}
	resp.On("SendUDPResponse", net.UDPAddr{
		IP:   net.IPv4(88, 200, 23, 12),
		Port: 40975,
	}, []byte("Pong")).Once()

	sh.DatagramRequestHandler(context.TODO(), resp, DatagramRequest{
		data: []byte("Ping"),
		rAddr: net.UDPAddr{
			IP:   net.IPv4(88, 200, 23, 12),
			Port: 40975,
		},
	})

	resp.AssertExpectations(t)
}
