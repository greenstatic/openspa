package main

import (
	"crypto/rand"
	"fmt"
	"github.com/greenstatic/openspa/openspalib/tlv8"
)

func main() {
	c := tlv8.NewContainer()

	c.Add(tlv8.Item{
		Type:  0x01,
		Value: []byte{1,2,3},
	})
	c.Add(tlv8.Item{
		Type:  0x01,
		Value: []byte{11,12,13},
	})
	c.Add(tlv8.Item{
		Type:  0x02,
		Value: []byte{42},
	})
	dataB := make([]byte, 300)
	rand.Read(dataB)
	c.Add(tlv8.Item{
		Type:  0x01,
		Value: dataB,
	})


	b, err := c.Bytes()
	panicErr(err)

	c, err = tlv8.Parse(b)
	panicErr(err)

	assert(len(c.Get(0x01)), 3)
	assert(len(c.Get(0x02)), 1)
	assert(len(c.Get(0x01)[0].Value), 3)
	assert(len(c.Get(0x01)[1].Value), 3)
	assert(len(c.Get(0x01)[2].Value), 300)
	assert(len(c.Get(0x02)[0].Value), 1)

}

func panicErr(err error) {
	if err != nil {
		panic(err)
	}
}

func assert(a, b int) {
	if a != b {
		panic(fmt.Sprintf("assert failed %d != %d", a, b))
	}
}