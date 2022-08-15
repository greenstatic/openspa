package tlv

import (
	"bytes"
	"fmt"
	"io"

	"github.com/emirpasic/gods/lists/doublylinkedlist"
	"github.com/pkg/errors"
)

type ErrInvalidTLV8EncodedBuffer string

func (e ErrInvalidTLV8EncodedBuffer) Error() string {
	return fmt.Sprintf("invalid tlv encoded buffer: %s", string(e))
}

const (
	ErrNoSeparator               = ErrInvalidTLV8EncodedBuffer("no separator between two items")
	ErrBadFragment               = ErrInvalidTLV8EncodedBuffer("bad fragment")
	ErrOutOfBounds               = ErrInvalidTLV8EncodedBuffer("out of bounds dues to bad length field")
	ErrFragmentItemInvalidLength = ErrInvalidTLV8EncodedBuffer("fragment item invalid length")
	ErrTooShort                  = ErrInvalidTLV8EncodedBuffer("too short")
)

func NewContainer() Container {
	return newContainer()
}

func UnmarshalTLVContainer(b []byte) (Container, error) {
	return unmarshalContainer(b)
}

var _ Container = &container{}

type container struct {
	items *doublylinkedlist.List
}

func newContainer() *container {
	c := &container{}
	c.items = doublylinkedlist.New()
	return c
}

func (c *container) GetByte(key uint8) (b byte, exists bool) {
	bx, e := c.GetBytes(key)
	if !e || len(bx) == 0 {
		return 0, false
	}
	return bx[0], true
}

func (c *container) GetBytes(key uint8) (b []byte, exists bool) {
	it := c.items.Iterator()
	for it.Next() {
		value := it.Value()
		item, ok := value.(Item)
		if !ok {
			panic(errors.New("type assert failed"))
		}
		if item.Type == key {
			return item.Value, true
		}
	}

	return nil, false
}

func (c *container) SetByte(key uint8, value byte) {
	c.SetBytes(key, []byte{value})
}

func (c *container) SetBytes(key uint8, value []byte) {
	if key == itemTypeSeparator {
		panic("reserved key")
	}

	i := Item{
		Type:  key,
		Value: value,
	}

	c.items.Add(i)
}

func (c *container) Remove(key uint8) {
	done := false
	for !done {
		it := c.items.Iterator()
		for it.Next() {
			index, value := it.Index(), it.Value()
			item, ok := value.(Item)
			if !ok {
				panic(errors.New("type assert failed"))
			}

			if item.Type == key {
				c.items.Remove(index)
				break
			}
		}
		done = true
	}

}

func (c *container) Bytes() []byte {
	b := &bytes.Buffer{}
	_ = c.output(b)
	return b.Bytes()
}

func (c *container) output(w io.Writer) error {
	previousItemType := itemTypeSeparator
	it := c.items.Iterator()
	for it.Next() {
		value := it.Value()
		item, ok := value.(Item)
		if !ok {
			panic("type assert failed")
		}

		if previousItemType == item.Type {
			if err := itemSeparatorOutput(w); err != nil {
				return err
			}
		}

		if err := item.output(w); err != nil {
			return err
		}
		previousItemType = item.Type
	}

	return nil
}

// NoEntries returns the number of entries in the container
func (c *container) NoEntries() int {
	return c.items.Size()
}

func unmarshalContainer(b []byte) (*container, error) {
	c := newContainer()

	items, err := parse(b)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		c.SetBytes(item.Type, item.Value)
	}

	return c, nil
}

func parse(b []byte) ([]Item, error) {
	var err error

	if len(b) < 2 {
		// An encoded TLV8 container requires at least 1 item, the smallest item is
		// an item with a Type and Length.
		// A separator is technically smaller (only Type field), but the separator item
		// is a special item used only for encoding, not for user data. So from this point
		// of view, we can ignore it.
		if len(b) == 1 {
			if b[0] != itemTypeSeparator {
				err = ErrTooShort
			}
		}
		return []Item{}, err
	}

	items := make([]Item, 0, 8)

	previousItem := itemSeparator
	isFragment := false

	i := 0
	for {
		if i+1 >= len(b) {
			// We need at least a Type and Value
			break
		}

		itemType := b[i]

		if itemType == itemTypeSeparator {
			isFragment = false
			previousItem = itemSeparator
			i++
			continue
		}

		if previousItem.Type == itemType {
			if isFragment && len(previousItem.Value) != itemLengthMax {
				// Previous fragment item should have been the last
				err = ErrBadFragment
				break
			}

			if !isFragment && len(previousItem.Value) != itemLengthMax {
				err = ErrNoSeparator
				break
			}
			if len(previousItem.Value) == itemLengthMax {
				// We have entered into a fragmented item
				isFragment = true
			}
		} else {
			if isFragment {
				isFragment = false
			}
		}

		itemLength := int(uint(b[i+1]))

		if !(i+itemLength+1 < len(b)) {
			// Item length out of bound, stop
			err = ErrOutOfBounds
			break
		}
		var item Item

		if itemLength == 0 {
			if isFragment {
				err = ErrFragmentItemInvalidLength
				break
			}
			item = Item{
				Type:  itemType,
				Value: []byte{},
			}
			items = append(items, item)
		} else {
			// careful, this item is a fragmented item
			vb := make([]byte, itemLength)
			copy(vb, b[i+2:i+2+itemLength])

			item = Item{
				Type:  itemType,
				Value: vb,
			}

			if isFragment {
				fItem := items[len(items)-1]
				fItem.Value = append(fItem.Value, item.Value...)
				items[len(items)-1] = fItem
			} else {
				items = append(items, item)
			}
		}

		i += 2 + itemLength
		previousItem = item
	}

	return items, err
}
