package tlv8

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input  []byte
		output []Item
		err    error
	}{
		{
			// Test case #1
			input:  nil,
			output: []Item{},
			err:    nil,
		},
		{
			// Test case #2
			input:  []byte{},
			output: []Item{},
			err:    nil,
		},
		{
			// Test case #3
			input:  []byte{0x00},
			output: []Item{},
			err:    nil,
		},
		{
			// Test case #4
			input: []byte{0x01, 0x00},
			output: []Item{
				{
					Type:  0x01,
					Value: []byte{},
				},
			},
			err: nil,
		},
		{
			// Test case #5
			input:  []byte{0x01, 0x01},
			output: []Item{},
			err:    ErrOutOfBounds,
		},
		{
			// Test case #6
			input: []byte{0x01, 0x01, 0x66},
			output: []Item{
				{
					Type:  0x01,
					Value: []byte{0x66},
				},
			},
			err: nil,
		},
		{
			// Test case #7
			input: []byte{0x01, 0x01, 0x66, 0x01, 0x01, 0x66},
			output: []Item{
				{
					Type:  0x01,
					Value: []byte{0x66},
				},
			},
			err: ErrNoSeparator,
		},
		{
			// Test case #8
			input: []byte{0x01, 0x01, 0x66, 0x00, 0x01, 0x01, 0x66},
			output: []Item{
				{
					Type:  0x01,
					Value: []byte{0x66},
				},
				{
					Type:  0x01,
					Value: []byte{0x66},
				},
			},
			err: nil,
		},
		{
			// Test case #9
			input: []byte{0x01, 0x05, 0x66, 0x00, 0x01, 0x01, 0x66},
			output: []Item{
				{
					Type:  0x01,
					Value: []byte{0x66, 0x00, 0x01, 0x01, 0x66},
				},
			},
			err: nil,
		},
		{
			// Test case #10
			input:  []byte{0x10},
			output: []Item{},
			err:    ErrTooShort,
		},
	}

	for i, test := range tests {
		testNo := i + 1
		out, err := parse(test.input)

		if !itemSliceEqual(test.output, out) {
			t.Errorf("Test case: %d, output mismatch\n%v != %v", testNo, test.output, out)
		}

		if test.err != err {
			t.Errorf("Test case: %d, err mismatch\n%v != %v", testNo, test.err, err)
		}

	}
}

func TestParse_Zero(t *testing.T) {
	for i := 1; i <= 4; i++ {
		b := bytes.Buffer{}
		for j := 1; i < i; j++ {
			b.WriteByte(0x00)
		}

		output, err := parse(b.Bytes())

		if len(output) != 0 {
			t.Errorf("output should be an empty slice")
		}

		if err != nil {
			t.Error(err)
		}
	}
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

	if !itemSliceEqual(ix, correctResult) {
		t.Error("item slice mismatch")
	}
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

	if !itemSliceEqual(ix, correctResult) {
		t.Error("item slice mismatch")
	}
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

	if !itemSliceEqual(ix, correctResult) {
		t.Error("item slice mismatch")
	}
}

func TestBytes(t *testing.T) {
	tests := []struct {
		input  []Item
		output []byte
	}{
		{
			// Test case #1
			input:  nil,
			output: []byte{},
		},
		{
			// Test case #2
			input:  []Item{},
			output: []byte{},
		},
		{
			// Test case #3
			input: []Item{
				{
					Type:  0x01,
					Value: []byte{0x04},
				},
			},
			output: []byte{0x01, 0x01, 0x04},
		},
		{
			// Test case #4
			input: []Item{
				{
					Type:  0x01,
					Value: []byte{0x04},
				},
				{
					Type:  0x02,
					Value: []byte{0x01},
				},
			},
			output: []byte{0x01, 0x01, 0x04, 0x02, 0x01, 0x1},
		},
		{
			// Test case #5
			input: []Item{
				{
					Type:  0x01,
					Value: []byte{0x04},
				},
				{
					Type:  0x01,
					Value: []byte{0x01},
				},
			},
			output: []byte{0x01, 0x01, 0x04, 0x0, 0x01, 0x01, 0x1},
		},
		{
			// Test case #5
			input: []Item{
				{
					Type:  0x01,
					Value: []byte{0x04},
				},
				{
					Type:  0x01,
					Value: []byte{},
				},
			},
			output: []byte{0x01, 0x01, 0x04, 0x0, 0x01, 0x00},
		},
	}

	for i, test := range tests {
		testNo := i + 1

		c := NewContainer()
		c.items = test.input

		out, err := c.Bytes()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(test.output, out) {
			t.Errorf("Test case: %d, output mismatch\n%v != %v", testNo, test.output, out)
		}
	}
}

func TestBytesWithFragmentation(t *testing.T) {
	dataB := make([]byte, 300)
	rand.Read(dataB)

	c := NewContainer()
	c.items = []Item{
		{
			Type:  0x01,
			Value: dataB,
		},
	}

	correctOut := bytes.Buffer{}
	correctOut.WriteByte(0x01)     // Type
	correctOut.WriteByte(0xFF)     // Length
	correctOut.Write(dataB[:0xFF]) // Value
	correctOut.WriteByte(0x01)     // Type
	correctOut.WriteByte(45)       // Length
	correctOut.Write(dataB[0xFF:]) // Value

	correctOutB := correctOut.Bytes()
	out, err := c.Bytes()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(correctOutB, out) {
		t.Error("Bytes mismatch")
	}
}

func itemSliceEqual(a, b []Item) bool {
	if len(a) != len(b) {
		return false
	}

	if (a == nil && b != nil) || (a != nil && b == nil) {
		return false
	}

	for i := range a {
		if !itemEqual(a[i], b[i]) {
			return false
		}
	}

	return true
}

func itemEqual(a, b Item) bool {
	if a.Type != b.Type {
		return false
	}

	if len(a.Value) != len(b.Value) {
		return false
	}

	return bytes.Equal(a.Value, b.Value)
}

func BenchmarkParse(b *testing.B) {
	data := []byte{0x01, 0x01, 0x66, 0x00, 0x01, 0x01, 0x66}
	for i := 0; i < b.N; i++ {
		parse(data)
	}
}
