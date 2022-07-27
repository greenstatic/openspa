package tlv

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerGetByte_ExistingKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{11})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetByte(0x01)
	assert.True(t, exists)
	assert.Equal(t, byte(11), b)
}

func TestContainerGetByte_ExistingKeyButBytes(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{11, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetByte(0x01)
	assert.True(t, exists)
	assert.Equal(t, byte(11), b)
}

func TestContainerGetByte_ExistingKeyButEmpty(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetByte(0x01)
	assert.False(t, exists)
	assert.Equal(t, byte(0), b)
}

func TestContainerGetByte_NonExistingKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{1, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetByte(0x03)
	assert.False(t, exists)
	assert.Equal(t, byte(0), b)
}

func TestContainerGetBytes_ExistingKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{11})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetBytes(0x01)
	assert.True(t, exists)
	assert.Equal(t, []byte{11}, b)
}

func TestContainerGetBytes_ExistingKey2(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{11, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetBytes(0x01)
	assert.True(t, exists)
	assert.Equal(t, []byte{11, 3, 2}, b)
}

func TestContainerGetBytes_ExistingKeyButEmpty(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetBytes(0x01)
	assert.True(t, exists)
	assert.Equal(t, []byte{}, b)
}

func TestContainerGetBytes_NonExistingKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{1, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	b, exists := c.GetBytes(0x03)
	assert.False(t, exists)
	assert.Nil(t, b)
}

func TestContainerSetByte(t *testing.T) {
	c := newContainer()

	assert.Equal(t, 0, c.NoEntries())

	c.SetByte(1, 11)
	assert.Equal(t, 1, c.NoEntries())
	b, exists := c.GetByte(1)
	assert.True(t, exists)
	assert.Equal(t, byte(11), b)

	c.SetByte(1, 0)
	assert.Equal(t, 2, c.NoEntries())
	b, exists = c.GetByte(1)
	assert.True(t, exists)
	assert.Equal(t, byte(11), b)

	c.SetByte(2, 12)
	assert.Equal(t, 3, c.NoEntries())
	b, exists = c.GetByte(2)
	assert.True(t, exists)
	assert.Equal(t, byte(12), b)
}

func TestContainerSetByte_Type0ShouldPanic(t *testing.T) {
	c := newContainer()

	assert.PanicsWithValue(t, "reserved key", func() {
		c.SetByte(0, 9)
	})
}

func TestContainerSetBytes(t *testing.T) {
	c := newContainer()

	assert.Equal(t, 0, c.NoEntries())

	c.SetBytes(1, []byte{})
	assert.Equal(t, 1, c.NoEntries())

	c.SetBytes(1, []byte{})
	assert.Equal(t, 2, c.NoEntries())

	c.SetBytes(2, []byte{})
	assert.Equal(t, 3, c.NoEntries())
}

func TestContainerSetBytes_Type0ShouldPanic(t *testing.T) {
	c := newContainer()

	assert.PanicsWithValue(t, "reserved key", func() {
		c.SetBytes(0, []byte{})
	})
}

func TestContainerRemove_NonExistentKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{1, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	c.Remove(0x03)
	assert.Equal(t, 2, c.NoEntries())
}

func TestContainerRemove_ExistingKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{1, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	c.Remove(0x02)
	assert.Equal(t, 1, c.NoEntries())

	_, exists := c.GetBytes(0x01)
	assert.True(t, exists)

	_, exists = c.GetBytes(0x02)
	assert.False(t, exists)
}

func TestContainerBytes_Empty(t *testing.T) {
	c := newContainer()

	assert.Equal(t, 0, c.NoEntries())

	b := c.Bytes()
	assert.Empty(t, b)
}

func TestContainerBytes_1EmptyItem(t *testing.T) {
	c := newContainer()
	c.SetBytes(1, []byte{})

	assert.Equal(t, 1, c.NoEntries())

	b := c.Bytes()
	assert.Equal(t, []byte{1, 0}, b)
}

func TestContainerBytes_1Item(t *testing.T) {
	c := newContainer()
	c.SetBytes(1, []byte{1, 2, 3})

	assert.Equal(t, 1, c.NoEntries())

	b := c.Bytes()
	assert.Equal(t, []byte{1, 3, 1, 2, 3}, b)
}

func TestContainerBytes_2Items(t *testing.T) {
	c := newContainer()
	c.SetBytes(1, []byte{1, 2, 3})
	c.SetBytes(2, []byte{4, 5, 6})

	assert.Equal(t, 2, c.NoEntries())

	b := c.Bytes()
	assert.Equal(t, []byte{
		1, 3, 1, 2, 3,
		2, 3, 4, 5, 6,
	}, b)
}

func TestContainerBytes_2ItemsWithSameKey(t *testing.T) {
	c := newContainer()
	c.SetBytes(1, []byte{1, 2, 3})
	c.SetBytes(1, []byte{4, 5, 6})

	assert.Equal(t, 2, c.NoEntries())

	b := c.Bytes()
	assert.Equal(t, []byte{
		1, 3, 1, 2, 3,
		0,
		1, 3, 4, 5, 6,
	}, b)
}

func TestContainerNoEntries_Empty(t *testing.T) {
	c := newContainer()

	count := c.NoEntries()
	assert.Equal(t, 0, count)
}

func TestContainerNoEntries_NonEmpty(t *testing.T) {
	c := newContainer()
	c.SetBytes(0x01, []byte{1, 3, 2})
	c.SetBytes(0x02, []byte{5, 1, 3})

	assert.Equal(t, 2, c.NoEntries())
}

func TestParse_EmptySlice(t *testing.T) {
	itx, err := parse([]byte{})
	assert.NoError(t, err)
	assert.Empty(t, itx)
}

func TestParse_SingleSeparator(t *testing.T) {
	itx, err := parse([]byte{0x00})
	assert.NoError(t, err)
	assert.Empty(t, itx)
}

func TestParse_SingleEmptyItem(t *testing.T) {
	itx, err := parse([]byte{0x01, 0x00})
	assert.NoError(t, err)
	require.Len(t, itx, 1)

	assert.Equal(t, byte(0x01), itx[0].Type)
	assert.Empty(t, itx[0].Value)
}

func TestParse_SingleItem(t *testing.T) {
	itx, err := parse([]byte{0x10, 0x02, 0x09, 0x0A})
	assert.NoError(t, err)
	require.Len(t, itx, 1)

	assert.Equal(t, byte(0x10), itx[0].Type)
	assert.Equal(t, []byte{0x09, 0x0A}, itx[0].Value)
}

func TestParse_TwoItem(t *testing.T) {
	itx, err := parse([]byte{
		0x10, 0x02, 0x09, 0x0A,
		0x11, 0x01, 0x04,
	})
	assert.NoError(t, err)
	require.Len(t, itx, 2)

	assert.Equal(t, byte(0x10), itx[0].Type)
	assert.Equal(t, []byte{0x09, 0x0A}, itx[0].Value)

	assert.Equal(t, byte(0x11), itx[1].Type)
	assert.Equal(t, []byte{0x04}, itx[1].Value)
}

func TestParse_ErrOutOfBounds(t *testing.T) {
	_, err := parse([]byte{
		0x10, 0x02, 0x09, 0x0A,
		0x11, 0x02, 0x04,
	})
	assert.ErrorIs(t, err, ErrOutOfBounds)
}

func TestParse_ErrNoSeparator(t *testing.T) {
	_, err := parse([]byte{
		0x01, 0x01, 0x66,
		0x01, 0x01, 0x66,
	})
	assert.ErrorIs(t, err, ErrNoSeparator)
}

func TestParse_ErrTooShort(t *testing.T) {
	_, err := parse([]byte{0x0A})
	assert.ErrorIs(t, err, ErrTooShort)
}

func TestParse_Fragmentation1(t *testing.T) {
	b := bytes.Buffer{}

	dataB := make([]byte, 255)
	for i := range dataB {
		dataB[i] = uint8(i)
	}
	dataB2 := make([]byte, 14)
	for i := range dataB {
		dataB[i] = uint8(i)
	}

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x01)               // Type
	b.WriteByte(uint8(len(dataB2))) // Length
	b.Write(dataB2)

	b.WriteByte(0x02) // Type
	b.WriteByte(0x01) // Length
	b.WriteByte(0x03) // Value

	b.WriteByte(0x01) // Type
	b.WriteByte(0x01) // Length
	b.WriteByte(0x04) // Value

	ix, err := parse(b.Bytes())
	if err != nil {
		t.Error(err)
	}

	correctResult := []Item{
		{
			Type:  0x01,
			Value: append(dataB, append(dataB, dataB2...)...),
		},
		{
			Type:  0x02,
			Value: []byte{0x03},
		},
		{
			Type:  0x01,
			Value: []byte{0x04},
		},
	}

	assert.Equal(t, correctResult, ix)
}

func TestParse_Fragmentation2(t *testing.T) {
	b := bytes.Buffer{}

	dataB := make([]byte, 255)
	for i := range dataB {
		dataB[i] = uint8(i)
	}

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x00) // Separator

	b.WriteByte(0x01) // Type
	b.WriteByte(0x01) // Length
	b.WriteByte(0x04) // Value

	b.WriteByte(0x02) // Type
	b.WriteByte(0x01) // Length
	b.WriteByte(0x03) // Value

	ix, err := parse(b.Bytes())
	if err != nil {
		t.Error(err)
	}

	correctResult := []Item{
		{
			Type:  0x01,
			Value: append(dataB, append(dataB, dataB...)...),
		},
		{
			Type:  0x01,
			Value: []byte{0x04},
		},
		{
			Type:  0x02,
			Value: []byte{0x03},
		},
	}

	assert.Equal(t, correctResult, ix)
}

func TestParse_Fragmentation3(t *testing.T) {
	b := bytes.Buffer{}

	dataB := make([]byte, 255)
	for i := range dataB {
		dataB[i] = uint8(i)
	}

	b.WriteByte(0x01)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	b.WriteByte(0x02)              // Type
	b.WriteByte(uint8(len(dataB))) // Length
	b.Write(dataB)

	ix, err := parse(b.Bytes())
	if err != nil {
		t.Error(err)
	}

	correctResult := []Item{
		{
			Type:  0x01,
			Value: dataB,
		},
		{
			Type:  0x02,
			Value: dataB,
		},
	}

	assert.Equal(t, correctResult, ix)
}

func TestBytesWithFragmentation(t *testing.T) {
	dataB := make([]byte, 300)
	rand.Read(dataB)

	c := NewContainer()
	c.SetBytes(0x01, dataB)

	correctOut := bytes.Buffer{}
	correctOut.WriteByte(0x01)     // Type
	correctOut.WriteByte(0xFF)     // Length
	correctOut.Write(dataB[:0xFF]) // Value
	correctOut.WriteByte(0x01)     // Type
	correctOut.WriteByte(45)       // Length
	correctOut.Write(dataB[0xFF:]) // Value

	correctOutB := correctOut.Bytes()
	out := c.Bytes()
	assert.Equal(t, correctOutB, out)
}
