package tlv

import "io"

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

func (item *Item) output(w io.Writer) error {
	if item.Type == itemTypeSeparator {
		// Type, Length & Value omitted
		return itemSeparatorOutput(w)
	}

	if len(item.Value) == 0 {
		// Type & Length=0, Value omitted
		_, err := w.Write([]byte{item.Type, 0x00})
		return err
	}

	// Fragment the item if required
	for i := 0; i < len(item.Value); i += itemLengthMax {
		rem := len(item.Value) - i
		if rem > itemLengthMax {
			rem = itemLengthMax
		}

		b := item.Value[i : i+rem]
		_, err := w.Write([]byte{item.Type, uint8(len(b))})
		if err != nil {
			return err
		}

		_, err = w.Write(b)
		if err != nil {
			return err
		}
	}

	return nil
}

func itemSeparatorOutput(w io.Writer) error {
	_, err := w.Write([]byte{itemTypeSeparator})
	return err
}
