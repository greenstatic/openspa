package tlv8

import (
	"bytes"
	"io"
)

type Container struct {
	items []Item
}

func NewContainer() Container {
	c := Container{
		items: []Item{},
	}
	return c
}

func (c *Container) Add(i Item) {
	if i.Type == itemTypeSeparator {
		panic("reserved item type")
	}
	c.items = append(c.items, i)
}

func (c *Container) AddMultiple(i []Item) {
	for _, item := range i {
		c.Add(item)
	}
}

func (c *Container) Get(itemType uint8) []Item {
	result := make([]Item, 0)
	for _, item := range c.items {
		if item.Type == itemType {
			item2 := item // make a copy
			result = append(result, item2)
		}
	}
	return result
}

func (c *Container) GetFirst(itemType uint8) (Item, bool) {
	for _, item := range c.items {
		if item.Type == itemType {
			return item, true
		}
	}
	return Item{}, false
}

func (c *Container) GetAll() []Item {
	return c.items
}

func (c *Container) output(w io.Writer) error {
	previousItemType := itemTypeSeparator
	for _, item := range c.items {
		if previousItemType == item.Type {
			itemSeparatorOutput(w)
		}

		item.output(w)
		previousItemType = item.Type
	}

	return nil
}

func (c *Container) Output(w io.Writer) error {
	return c.output(w)
}

func (c *Container) Bytes() ([]byte, error) {
	b := bytes.Buffer{}
	err := c.output(&b)
	return b.Bytes(), err
}

func Parse(b []byte) (Container, error) {
	c := NewContainer()
	i, err := parse(b)
	c.AddMultiple(i)
	return c, err
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
			item = Item{
				Type:  itemType,
				Value: b[i+2 : i+2+itemLength],
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
