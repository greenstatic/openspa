package openspalib

import (
	"bytes"
	"testing"

	"github.com/greenstatic/go-tlv/tlv"
)

func TestTlvDecode(t *testing.T) {
	data := []byte{
		0x01, 0x23, 0x00, 0x03, 0x32, 0x22, 0x42, // Tag 1
		0x00, 0x00, 0x00, 0x01, 0x02, // Tag 2
		0x12, 0x00, 0x00, 0x02, 0x5F, 0xFF, // Tag 3
	}

	dataValue1 := []byte{0x32, 0x22, 0x42}
	dataValue2 := []byte{0x2}
	dataValue3 := []byte{0x5F, 0xFF}

	n, err := tlv.ParseBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	r1, ok := n.GetFirstByTag(0x0123)
	if !ok {
		t.Fatal("Failed to find tag 1")
	}

	if !bytes.Equal(dataValue1, r1.Value) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r1.Value)
	}

	r2, ok := n.GetFirstByTag(0x0000)
	if !ok {
		t.Fatal("Failed to find tag 2")
	}

	if !bytes.Equal(dataValue2, r2.Value) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r2.Value)
	}

	r3, ok := n.GetFirstByTag(0x1200)
	if !ok {
		t.Fatal("Failed to find tag 3")
	}

	if !bytes.Equal(dataValue3, r3.Value) {
		t.Errorf("Bytes don't match %x != %x", dataValue1, r3.Value)
	}
}
