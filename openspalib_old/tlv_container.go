package openspalib_old

import (
	"bytes"
	"io"

	"github.com/greenstatic/openspa/openspalib_old/tlv21"
	"github.com/pkg/errors"
)

type TLVContainer interface {
	GetByte(typeKey uint16) (b byte, exists bool)
	GetBytes(typeKey uint16) (b []byte, exists bool)

	SetByte(typeKey uint16, value byte)
	SetBytes(typeKey uint16, value []byte)

	Remove(typeKey uint16) bool

	// BytesBuffer returns the container encoded in bytes as a bytes buffer
	BytesBuffer() *bytes.Buffer
	// Bytes returns the container encoded as a slice of bytes
	Bytes() []byte

	// Size returns the length of the byte slice or buffer
	Size() int

	// NoEntries returns the number of nodes in the container
	NoEntries() int

	// Merge merges the input parameter container with the container on which it is called and returns the merged
	// container. All data is copied, no modifications are made to either input containers.
	Merge(c TLVContainer) (TLVContainer, error)
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

func NewEmptyTLVContainer() TLVContainer {
	c, err := tlv21.NewContainer(nil)
	if err != nil {
		panic(err)
	}
	return &tlvContainer{
		container: c,
	}
}

func (c *tlvContainer) SetByte(typeKey uint16, value byte) {
	c.SetBytes(typeKey, []byte{value})
}

func (c *tlvContainer) SetBytes(typeKey uint16, value []byte) {
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

func (c *tlvContainer) Remove(typeKey uint16) bool {
	return c.container.RemoveEntry(tlv21.Tag(typeKey))
}

func (c *tlvContainer) BytesBuffer() *bytes.Buffer {
	return c.container.BytesBuffer()
}

func (c *tlvContainer) Size() int {
	return c.BytesBuffer().Len()
}

func (c *tlvContainer) Bytes() []byte {
	b, err := io.ReadAll(c.BytesBuffer())
	if err != nil {
		panic(err)
	}
	return b
}

func (c *tlvContainer) NoEntries() int {
	return c.container.NoEntries()
}

func (c *tlvContainer) Merge(c2 TLVContainer) (TLVContainer, error) {
	b, err := io.ReadAll(c.BytesBuffer())
	if err != nil {
		return nil, errors.Wrap(err, "primary container buffer read")
	}

	b2 := make([]byte, 0)
	if c2 != nil {
		b2, err = io.ReadAll(c2.BytesBuffer())
		if err != nil {
			return nil, errors.Wrap(err, "inputted container buffer read")
		}
	}

	b = append(b, b2...)

	buff := bytes.NewBuffer(b)

	con, err := tlv21.NewContainer(buff)
	if err != nil {
		return nil, errors.Wrap(err, "new container")
	}

	return &tlvContainer{
		container: con,
	}, nil
}
