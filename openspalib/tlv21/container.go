package tlv21

import (
	"bytes"
	"github.com/pkg/errors"
	"io"
)

type Container struct {
	nodes []node
}

func NewContainer(r io.Reader) (Container, error) {
	if r != nil {
		return Parse(r)
	}
	c := Container{
		nodes: []node{},
	}

	return c, nil
}

func (c *Container) SetEntry(tag Tag, b []byte) {
	bCopy := make([]byte, len(b))
	copy(bCopy, b)

	n := node{
		tag: tag,
		value:   bCopy,
	}

	c.addNode(n)
}

func (c *Container) Entry(tag Tag) ([]byte, bool) {
	for _, n := range c.nodes {
		if n.tag == tag {
			return n.value, true
		}
	}

	return nil, false
}

func (c *Container) addNode(n node) {
	c.nodes = append(c.nodes, n)
}

func (c *Container) BytesBuffer() *bytes.Buffer {
	b := bytes.Buffer{}

	for _, n := range c.nodes {
		bTmp, err := io.ReadAll(n.Bytes())
		if err != nil {
			panic(err)
		}

		b.Write(bTmp)
	}

	return &b
}

func (c *Container) Bytes() io.Reader {
	return c.BytesBuffer()
}

func (c *Container) NoEntries() int {
	return len(c.nodes)
}

func Parse(r io.Reader) (Container, error) {
	n, err := nodeParse(r)
	if err != nil {
		return Container{}, errors.Wrap(err, "parsing nodes")
	}

	return Container{
		nodes: n,
	}, nil
}
