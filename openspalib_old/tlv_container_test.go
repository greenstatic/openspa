package openspalib_old

import (
	"bytes"
	"io"
	"testing"
)

func TestTlvDecode(t *testing.T) {
	data := []byte{
		0x01, 0x23, 0x03, 0x32, 0x22, 0x42, // Tag 1
		0x00, 0x00, 0x01, 0x02, // Tag 2
		0x12, 0x00, 0x02, 0x5F, 0xFF, // Tag 3
	}

	dataValue1 := []byte{0x32, 0x22, 0x42}
	dataValue2 := []byte{0x2}
	dataValue3 := []byte{0x5F, 0xFF}

	c, err := NewTLVContainer(data)
	if err != nil {
		t.Fatal(err)
	}

	r1, ok := c.GetBytes(0x0123)
	if !ok {
		t.Fatal("Failed to find tag 0x0123")
	}

	if !bytes.Equal(dataValue1, r1) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r1)
	}

	r2, ok := c.GetBytes(0x0000)
	if !ok {
		t.Fatal("Failed to find tag 0x00")
	}

	if !bytes.Equal(dataValue2, r2) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r2)
	}

	r3, ok := c.GetBytes(0x1200)
	if !ok {
		t.Fatal("Failed to find tag 0x1200")
	}

	if !bytes.Equal(dataValue3, r3) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r3)
	}
}

func TestTlvMerge(t *testing.T) {
	c1, err := NewTLVContainer(nil)
	if err != nil {
		t.Fatal(err)
	}

	c1.SetBytes(0x1, []byte{0x12, 0x34, 0x56})
	c1.SetBytes(0x2, []byte{0xFA, 0xCA, 0x51})

	c2, err := NewTLVContainer(nil)
	if err != nil {
		t.Fatal(err)
	}
	c2.SetBytes(0x2, []byte{0xE1, 0x04, 0xC1})
	c2.SetBytes(0xA, []byte{0x00})

	c, err := c1.Merge(c2)
	if err != nil {
		t.Fatal(err)
	}

	b, err := io.ReadAll(c.BytesBuffer())
	if err != nil {
		t.Fatal(err)
	}

	expected := []byte{
		0x00, 0x01, 0x03, 0x12, 0x34, 0x56,
		0x00, 0x02, 0x06, 0xFA, 0xCA, 0x51, 0xE1, 0x04, 0xC1,
		0x00, 0x0A, 0x01, 0x00,
	}

	if !bytes.Equal(b, expected) {
		t.Errorf("\n%v \n!= \n%v", b, expected)
	}
}
