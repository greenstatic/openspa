package internal

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUDPServer(t *testing.T) {
	localhost := net.IPv4(127, 0, 0, 1).To4()

	h := NewDatagramRequestHandlerMock()
	h.On("DatagramRequestHandler", DatagramRequest{
		data: []byte("hello world!"),
		rAddr: net.UDPAddr{
			IP:   localhost,
			Port: 64534,
		},
	}).Once()

	s := NewUDPServer(localhost, 8083, h)
	done := make(chan bool)
	go func() {
		err := s.start()
		assert.NoError(t, err)
		done <- true
	}()

	go func() {
		time.Sleep(2 * time.Second)
		assert.NoError(t, s.stop())
	}()

	time.Sleep(100 * time.Millisecond)

	rAddr := &net.UDPAddr{
		IP:   localhost,
		Port: 8083,
	}

	c, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   localhost,
		Port: 64534,
	})
	assert.NoError(t, err)

	_, err = c.WriteToUDP([]byte("hello world!"), rAddr)
	assert.NoError(t, err)

	tm := time.NewTimer(5 * time.Second)
	select {
	case <-done:
	case <-tm.C:
		t.Error("Timeout")
	}

	h.AssertExpectations(t)
}

func TestRequestCoordinator_Size0ShouldBlock(t *testing.T) {
	r := NewRequestCoordinator(nil, 0)
	r.Start()

	done := make(chan bool)
	go func() {
		r.DatagramRequestHandler(context.TODO(), DatagramRequest{
			data: []byte{0x01},
			rAddr: net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8998,
			}})
		done <- true
	}()

	tm := time.NewTimer(2 * time.Second)
	select {
	case <-done:
		t.Fatal("Request is not blocking")
	case <-tm.C:
		<-r.queue
	}

	<-done
}

func TestRequestCoordinator_Size1ShouldNotBlock(t *testing.T) {
	r := NewRequestCoordinator(nil, 1)
	r.Start()

	done := make(chan bool)
	go func() {
		r.DatagramRequestHandler(context.TODO(), DatagramRequest{
			data: []byte{0x01},
			rAddr: net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8998,
			}})
		done <- true
	}()

	tm := time.NewTimer(2 * time.Second)
	select {
	case <-done:
	case <-tm.C:
		t.Fatal("Request is not blocking")
	}
}

func TestRequestCoordinator_ShouldCoordinate(t *testing.T) {
	h := NewDatagramRequestHandlerMock()
	h.On("DatagramRequestHandler", mock.Anything)

	r := NewRequestCoordinator(h, 1)
	r.Start()

	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			r.DatagramRequestHandler(context.TODO(), DatagramRequest{
				data: []byte{byte(i)},
				rAddr: net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 8998,
				}})
		}
		done <- true
	}()

	tm := time.NewTimer(3 * time.Second)
	select {
	case <-done:
		tm.Stop()
	case <-tm.C:
		t.Fatal("Blocked")
	}

	time.Sleep(time.Second)

	h.AssertNumberOfCalls(t, "DatagramRequestHandler", 100)
}

func TestRequestCoordinator_WorkAllocation(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(15)

	h := NewDatagramRequestHandlerStub(func(ctx context.Context, r DatagramRequest) {
		time.Sleep(time.Second)
		wg.Done()
	})

	r := NewRequestCoordinator(h, 10)
	r.Start()

	timeStart := time.Now()

	for i := 0; i < 15; i++ {
		go r.DatagramRequestHandler(context.TODO(), DatagramRequest{
			data: []byte{byte(i)},
			rAddr: net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 8998,
			}})
	}

	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	tm := time.NewTimer(15 * time.Second)
	select {
	case <-done:
		tm.Stop()
	case <-tm.C:
		t.Fatal("Timeout")
	}

	timeEnd := time.Now()

	diff := timeEnd.Sub(timeStart)

	assert.LessOrEqual(t, diff.Seconds(), 2.5)
	assert.GreaterOrEqual(t, diff.Seconds(), 2.0)
}
