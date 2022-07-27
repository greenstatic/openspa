package tlv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestItemOutput_ValueNil(t *testing.T) {
	i := Item{
		Type:  0x1,
		Value: nil,
	}

	b := &bytes.Buffer{}
	assert.NoError(t, i.output(b))

	assert.Equal(t, []byte{
		0x01,
		0x00,
	}, b.Bytes())
}

func TestItemOutput_ValueEmpty(t *testing.T) {
	i := Item{
		Type:  0x1,
		Value: []byte{},
	}

	b := &bytes.Buffer{}
	assert.NoError(t, i.output(b))

	assert.Equal(t, []byte{
		0x01,
		0x00,
	}, b.Bytes())
}

func TestItemOutput_Type0(t *testing.T) {
	i := Item{
		Type:  0x0,
		Value: []byte{1, 2, 3},
	}

	b := &bytes.Buffer{}
	assert.NoError(t, i.output(b))

	assert.Equal(t, []byte{
		0x00,
	}, b.Bytes())
}
