package tlv8

import "fmt"

type ErrInvalidTLV8EncodedBuffer string

func (e ErrInvalidTLV8EncodedBuffer) Error() string {
	return fmt.Sprintf("Invalid TLV8 encoded buffer: %s", string(e))
}

const (
	ErrNoSeparator               = ErrInvalidTLV8EncodedBuffer("no separator between two items")
	ErrBadFragment               = ErrInvalidTLV8EncodedBuffer("bad fragment")
	ErrOutOfBounds               = ErrInvalidTLV8EncodedBuffer("out of bounds dues to bad length field")
	ErrFragmentItemInvalidLength = ErrInvalidTLV8EncodedBuffer("fragment item invalid length")
	ErrTooShort                  = ErrInvalidTLV8EncodedBuffer("too short")
)
