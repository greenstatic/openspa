package tlv8

import (
	"io"
)

const (
	itemLengthMax           = 0xFF
	itemTypeSeparator uint8 = 0x00
)

var (
	itemSeparator = Item{
		Type:  itemTypeSeparator,
		Value: nil,
	}
)

type Item struct {
	Type  uint8
	Value []byte
}

func (item *Item) output(w io.Writer) {
	if item.Type == itemTypeSeparator {
		// Type, Length & Value omitted
		itemSeparatorOutput(w)
		return
	}

	if len(item.Value) == 0 {
		// Type & Length=0, Value omitted
		w.Write([]byte{item.Type, 0x00})
		return
	}

	// Fragment the item if required
	for i := 0; i < len(item.Value); i += itemLengthMax {
		rem := len(item.Value) - i
		if rem > itemLengthMax {
			rem = itemLengthMax
		}

		b := item.Value[i : i+rem]
		w.Write([]byte{item.Type, uint8(len(b))})
		w.Write(b)
	}
}

func itemSeparatorOutput(w io.Writer) {
	w.Write([]byte{itemTypeSeparator})
}
