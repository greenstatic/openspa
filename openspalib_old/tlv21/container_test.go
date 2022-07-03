package tlv21

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestContainerBasic(t *testing.T) {
	tests := []struct{
		tag   Tag
		input []byte
	}{
		// Test case: 1
		{
			0x01,
			[]byte{0x12, 0x23},
		},
		// Test case: 2
		{
			0x01,
			[]byte{0xAB, 0xCD},
		},
		// Test case: 3
		{
			0x01,
			randomByteSlice(300),
		},
		// Test case: 3
		{
			0x01,
			randomByteSlice(300),
		},
	}

	for i, test := range tests {
		testNo := i + 1
		c, err := NewContainer(nil)
		if err != nil {
			t.Fatal(err)
		}

		c.SetEntry(test.tag, test.input)
		result, found := c.Entry(test.tag)
		if !found {
			t.Errorf("Test case: %d failed. Entry %d not found", testNo, test.tag)
		}

		if !bytes.Equal(result, test.input) {
			t.Errorf("Test case: %d failed. %v != %v", testNo, result, test.input)
		}
	}
}

func TestContainerParse(t *testing.T) {
	buff := bytes.NewBuffer([]byte{
		0xAB, 0xCD, 0x01, 0xEF,        // TLV 1
		0x00, 0x01, 0x00,        	   // TLV 2
		0x00, 0x02, 0x02, 0x01, 0x02,  // TLV 3
		0x00, 0x02, 0x02, 0x03, 0x04,  // TLV 4
		0x00, 0x03, 0x02, 0x0A,        // TLV 5 - Wrong on purpose
	})

	c, err := NewContainer(buff)
	if err != nil {
		t.Fatal(err)
	}

	b, ok := c.Entry(0xABCD)
	if !ok {
		t.Fatal("Missing entry")
	}

	if b2 := []byte{0xEF}; !bytes.Equal(b, b2) {
		t.Fatalf("%v != %v", b, b2)
	}

	b, ok = c.Entry(0x01)
	if !ok {
		t.Fatal("Missing entry: 0x01")
	}

	if b2 := []byte{}; !bytes.Equal(b, b2) {
		t.Fatalf("%v != %v", b, b2)
	}

	b, ok = c.Entry(0x02)
	if !ok {
		t.Fatal("Missing entry: 0x02")
	}

	if b2 := []byte{0x01, 0x02, 0x03, 0x04}; !bytes.Equal(b, b2) {
		t.Fatalf("%v != %v", b, b2)
	}

	if _, ok = c.Entry(0x03); ok {
		t.Fatalf("Entry 0x03 should be missing")
	}

	// Check if we can remove entry
	if removed := c.RemoveEntry(0x02); !removed {
		t.Fatalf("Entry 0x02 was not removed")
	}

	if i := c.NoEntries(); i != 2 {
		t.Fatalf("2 != %d", i)
	}

}

func TestEmptySetEntry(t *testing.T) {
	c, err := NewContainer(nil)
	if err != nil {
		panic(err)
	}

	c.SetEntry(0x1234, nil)
	b := c.BytesBuffer().Bytes()
	if len(b) != 0 {
		t.Errorf("Buffer not empty but contains: %v", b)
	}
}

func randomByteSlice(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
