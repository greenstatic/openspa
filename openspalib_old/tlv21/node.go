package tlv21

import (
	"bytes"
	"encoding/binary"
	"github.com/pkg/errors"
	"io"
	"math"
)

const (
	maxLength = 0xFF
)

type Tag uint16

type node struct {
	tag   Tag
	value []byte
}

func (n *node) Bytes() io.Reader {
	b := bytes.Buffer{}

	tagB := make([]byte, 2)
	binary.BigEndian.PutUint16(tagB, uint16(n.tag))

	value := n.value
	length := len(value)

	// Value is empty, just write the Type and Length
	if length == 0 {
		b.Write(tagB)  // T
		b.WriteByte(uint8(0))  // L
		return &b
	}

	i := 0
	j := 0
	for {
		if length == 0 {
			break
		}

		j = int(math.Min(float64(maxLength), float64(length))) + i
		subValue := value[i:j]
		subValueLen := len(subValue)
		b.Write(tagB)  // T
		b.WriteByte(uint8(subValueLen))  // L
		b.Write(subValue)  // V

		length -= subValueLen
		i = j
	}

	return &b
}

func (n *node) Equal(i node) bool {
	if n.tag != i.tag {
		return false
	}

	return bytes.Equal(n.value, i.value)
}

func nodeParse(r io.Reader) ([]node, error) {
	n := make([]node, 0)
	tlSize := 3
	tl := make([]byte, tlSize)

	for {
		read, err := r.Read(tl) // Type + Length
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, errors.Wrap(err, "read")
		}

		if read != tlSize {
			// Not enough bytes to be TL (type and length)
			break
		}

		length := uint8(tl[0x2])

		value := make([]byte, length)  // Buffer for Value
		read, err = r.Read(value)

		if read != int(length) {
			// Invalid length field, ignore the TLV value
			continue
		}

		t := Tag(binary.BigEndian.Uint16(tl[:2]))

		found := false

		for i := range n {
			if n[i].tag == t {
				found = true
				n[i].value = append(n[i].value, value...)
				break
			}
		}
		if !found {
			n = append(n, node{
				tag:   t,
				value: value,
			})
		}
	}

	return n, nil
}
