package internal

import (
	"context"
	"net"

	"github.com/stretchr/testify/mock"
)

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerMock{}

type DatagramRequestHandlerMock struct {
	mock.Mock
}

func (d *DatagramRequestHandlerMock) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	d.Called(resp, r)
}

func NewDatagramRequestHandlerMock() *DatagramRequestHandlerMock {
	d := &DatagramRequestHandlerMock{}
	return d
}

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerStub{}

type DatagramRequestHandlerStub struct {
	f func(ctx context.Context, resp UDPResponser, r DatagramRequest)
}

func (d *DatagramRequestHandlerStub) DatagramRequestHandler(ctx context.Context, resp UDPResponser, r DatagramRequest) {
	d.f(ctx, resp, r)
}

//nolint:lll
func NewDatagramRequestHandlerStub(f func(ctx context.Context, resp UDPResponser, r DatagramRequest)) *DatagramRequestHandlerStub {
	d := &DatagramRequestHandlerStub{
		f: f,
	}
	return d
}

var _ UDPResponser = &UDPResponseMock{}

type UDPResponseMock struct {
	mock.Mock
}

func (u *UDPResponseMock) SendUDPResponse(dst net.UDPAddr, body []byte) error {
	args := u.Called(dst, body)
	return args.Error(0)
}
