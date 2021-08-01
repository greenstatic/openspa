package openspalib

import (
	"bytes"
	"github.com/greenstatic/openspa/openspalib/tlv21"
)

type TLVContainer interface {
	GetByte(typeKey uint16) (b byte, exists bool)
	GetBytes(typeKey uint16) (b []byte, exists bool)

	SetByte(typeKey uint16, value byte)
	SetBytes(typeKey uint16, value []byte)

	BytesBuffer() *bytes.Buffer
	BytesBufferLen() int

	NoEntries() int
}

type tlvContainer struct {
	container tlv21.Container
}

func NewTLVContainer(b []byte) (TLVContainer, error) {
	buff := make([]byte, len(b))
	copy(buff, b)

	buf := bytes.NewBuffer(buff)
	c, err := tlv21.NewContainer(buf)
	if err != nil {
		return nil, err
	}
	return &tlvContainer{
		container: c,
	}, nil
}

func (c *tlvContainer) SetByte(typeKey uint16, value byte) {
	c.SetBytes(typeKey, []byte{value})
}

func (c *tlvContainer) SetBytes(typeKey uint16, value []byte)  {
	c.container.SetEntry(tlv21.Tag(typeKey), value)
}

// GetByte returns the first byte of a potentially multi-byte key.
func (c *tlvContainer) GetByte(typeKey uint16) (b byte, exists bool) {
	buf, ok := c.GetBytes(typeKey)
	if !ok {
		return 0x00, false
	}

	if buf == nil || len(buf) == 0 {
		return 0x00, false
	}

	return buf[0], true
}

func (c *tlvContainer) GetBytes(typeKey uint16) (b []byte, exists bool) {
	return c.container.Entry(tlv21.Tag(typeKey))
}

func (c *tlvContainer) BytesBuffer() *bytes.Buffer {
	return c.container.BytesBuffer()
}

func (c *tlvContainer) BytesBufferLen() int {
	return c.BytesBuffer().Len()
}

func (c *tlvContainer) NoEntries() int {
	return c.container.NoEntries()
}