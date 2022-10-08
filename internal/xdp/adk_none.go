//go:build !xdp

//nolint:unused
package xdp

import "errors"

func IsSupported() bool {
	return false
}

type adk struct{}

var ErrNotSupported = errors.New("XDP support is not supported")

func NewADK(s ADKSettings, proof ADKProofGenerator) (ADK, error) {
	return nil, ErrNotSupported
}

func (a adk) Start() error {
	return ErrNotSupported
}

func (a adk) Stop() error {
	return ErrNotSupported
}

func (a adk) Stats() (Stats, error) {
	return Stats{}, ErrNotSupported
}
