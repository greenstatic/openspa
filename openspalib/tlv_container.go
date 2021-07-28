package openspalib

import (
	"bytes"
)

type TLVContainer interface {
	SetByte(typeKey uint16, value byte) error
	SetBytes(typeKey uint16, value []byte) error
	SetString(typeKey uint16, value string) error

	GetByte(typeKey uint16) (byte, bool, error)
	GetBytes(typeKey uint16) ([]byte, bool, error)
	GetString(typeKey uint16) (string, bool, error)

	BytesBuffer() *bytes.Buffer
	BytesBufferLen() int
	NoEntries() int
}

type tlvContainer struct {
	b []byte
}

func NewTLVContainer(b []byte, maxBufferSize int) TLVContainer {
	c := tlvContainer{b: b}
	return &c
}

func (c *tlvContainer) SetByte(typeKey uint16, value byte) error {
	// TODO
	return nil
}

func (c *tlvContainer) SetBytes(typeKey uint16, value []byte) error {
	// TODO
	return nil
}

func (c *tlvContainer) SetString(typeKey uint16, value string) error {
	// TODO
	return nil
}

func (c *tlvContainer) GetByte(typeKey uint16) (byte, bool, error) {
	// TODO
	return 0x00, false, nil
}

func (c *tlvContainer) GetBytes(typeKey uint16) ([]byte, bool, error) {
	// TODO
	return nil, false, nil
}

func (c *tlvContainer) GetString(typeKey uint16) (string, bool, error) {
	// TODO
	return "", false, nil
}

func (c *tlvContainer) BytesBuffer() *bytes.Buffer {
	if c == nil {
		return nil
	}
	return bytes.NewBuffer(c.b)
}

func (c *tlvContainer) BytesBufferLen() int {
	if c == nil {
		return 0
	}
	return len(c.b)
}

func (c *tlvContainer) NoEntries() int {
	return 0
}