package internal

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPServer(t *testing.T) {
	localhost := net.IPv4(127, 0, 0, 1).To4()

	h := NewHTTPServer(localhost, 8084)
	done := make(chan bool)
	go func() {
		err := h.Start()
		assert.NoError(t, err)
		done <- true
	}()

	time.Sleep(time.Second) // wait for the HTTP server to be ready

	c := http.DefaultClient
	c.Timeout = time.Second

	resp, err := c.Get("http://localhost:8084/")
	assert.NoError(t, err)
	assert.NotNil(t, resp)

	defer resp.Body.Close()

	respSpec := struct {
		Msg     string `json:"msg"`
		Version string `json:"version"`
	}{}

	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&respSpec))

	assert.Equal(t, "OpenSPA Server", respSpec.Msg)
	assert.Equal(t, Version(), respSpec.Version)

	assert.NoError(t, h.Stop())

	tm := time.NewTimer(5 * time.Second)
	select {
	case <-done:
	case <-tm.C:
		t.Error("Timeout")
	}
}
