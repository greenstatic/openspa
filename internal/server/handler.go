package server

import (
	"context"

	"github.com/greenstatic/openspa/pkg/openspalib"
)

type OpenSPAHandler struct {
}

func NewOpenSPAHandler() *OpenSPAHandler {
	o := &OpenSPAHandler{}
	return o
}

func (o *OpenSPAHandler) DatagramRequestHandler(ctx context.Context, r DatagramRequest) {
	req, err := openspalib.RequestUnmarshal(r.data)
	if err != nil {
		// TODO - log
		return
	}

	_ = req
	// TODO

}
