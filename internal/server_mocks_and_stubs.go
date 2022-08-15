package internal

import (
	"context"

	"github.com/stretchr/testify/mock"
)

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerMock{}

type DatagramRequestHandlerMock struct {
	mock.Mock
}

func (d *DatagramRequestHandlerMock) DatagramRequestHandler(ctx context.Context, r DatagramRequest) {
	d.Called(r)
}

func NewDatagramRequestHandlerMock() *DatagramRequestHandlerMock {
	d := &DatagramRequestHandlerMock{}
	return d
}

var _ UDPDatagramRequestHandler = &DatagramRequestHandlerStub{}

type DatagramRequestHandlerStub struct {
	f func(ctx context.Context, r DatagramRequest)
}

func (d *DatagramRequestHandlerStub) DatagramRequestHandler(ctx context.Context, r DatagramRequest) {
	d.f(ctx, r)
}

func NewDatagramRequestHandlerStub(f func(ctx context.Context, r DatagramRequest)) *DatagramRequestHandlerStub {
	d := &DatagramRequestHandlerStub{
		f: f,
	}
	return d
}
