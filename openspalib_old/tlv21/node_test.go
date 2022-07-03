package tlv21

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

var (
	nodeTestByteSlice1 = nodeTestPseudorandomSlice(7, 0xFE)
	nodeTestByteSlice2 = nodeTestPseudorandomSlice(7, 0xFF)
	nodeTestByteSlice3 = nodeTestPseudorandomSlice(7, 0x100)
	nodeTestByteSlice4 = nodeTestPseudorandomSlice(7, 0x1FE)
	nodeTestByteSlice5 = nodeTestPseudorandomSlice(7, 0x1FF)
)

func TestNodeBytes(t *testing.T) {
	tests := []struct{
		node node
		result []byte
	}{
		// Test case: 1
		{
			node{
				tag:   0x1234,
				value: []byte{0xAB,0xCD},
			},
			[]byte{0x12, 0x34, 0x02, 0xAB, 0xCD},
		},
		// Test case: 2
		{
			node{
				tag:   0x00,
				value: []byte{0xAB,0xCD},
			},
			[]byte{0x00, 0x00, 0x02, 0xAB, 0xCD},
		},
		// Test case: 3
		{
			node{
				tag:   0x01,
				value: []byte{},
			},
			[]byte{0x00, 0x01, 0x00},
		},
		// Test case: 4
		{
			node{
				tag:   0x01,
				value: nodeTestByteSlice1,
			},
			append([]byte{0x00, 0x01, 0xFE}, nodeTestByteSlice1...),
		},
		// Test case: 5
		{
			node{
				tag:   0x01,
				value: nodeTestByteSlice2,
			},
			append([]byte{0x00, 0x01, 0xFF}, nodeTestByteSlice2...),
		},
		// Test case: 6
		{
			node{
				tag:   0x01,
				value: nodeTestByteSlice3,
			},
			append(append(append(
				[]byte{0x00, 0x01, 0xFF}, nodeTestByteSlice3[:0xFF]...),
				[]byte{0x00, 0x01, 0x01}...), nodeTestByteSlice3[0xFF:]...),
		},
		// Test case: 7
		{
			node{
				tag:   0x01,
				value: nodeTestByteSlice4,
			},
			append(append(append(
				[]byte{0x00, 0x01, 0xFF}, nodeTestByteSlice4[:0xFF]...),
				[]byte{0x00, 0x01, 0xFF}...), nodeTestByteSlice4[0xFF:]...),
		},
		// Test case: 8
		{
			node{
				tag:   0x01,
				value: nodeTestByteSlice5,
			},
			append(append(append(append(append(
				[]byte{0x00, 0x01, 0xFF}, nodeTestByteSlice5[:0xFF]...),
				[]byte{0x00, 0x01, 0xFF}...), nodeTestByteSlice5[0xFF:0x1FE]...),
				[]byte{0x00, 0x01, 0x01}...), nodeTestByteSlice5[0x1FE:]...),
		},
	}

	for i, test := range tests {
		testNo := i + 1

		buf := test.node.Bytes()
		b, err := io.ReadAll(buf)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(b, test.result) {
			t.Errorf("Test case: %d failed. %v != %v", testNo, b, test.result)
		}
	}
}

func TestNodeParse(t *testing.T) {
	tests := []struct{
		input []byte
		want []node
	}{
		// Test case: 1
		{
			input:  []byte{
				0x00, 0x01, 0x01, 0xFA,
				0x00, 0x02, 0x02, 0x12, 0x34,
				0x00, 0x03, 0x00,
			},
			want: []node{
				{
					tag:   0x01,
					value: []byte{0xFA},
				},
				{
					tag:   0x02,
					value: []byte{0x12, 0x34},
				},
				{
					tag:   0x03,
					value: []byte{},
				},
			},
		},
		// Test case: 2
		{
			input: []byte{},
			want:  []node{},
		},
		// Test case: 3
		{
			input: []byte{
				0x00, 0x01, 0x01, 0x12,
				0x00, 0x01, 0x01, 0x34,
				0x00, 0x01, 0x01, 0x56,
			},
			want:  []node{
				{
					tag:   0x01,
					value: []byte{0x12, 0x34, 0x56},
				},
			},
		},
	}


	for i, test := range tests {
		testNo := i + 1

		buff := bytes.Buffer{}
		buff.Write(test.input)

		nodes, err := nodeParse(&buff)
		if err != nil {
			t.Fatal(err)
		}

		l1 := len(nodes)
		l2 := len(test.want)
		if l1 != l2 {
			t.Fatalf("Test case: %d failed, node count missmatch: %d != %d", testNo, l1, l2)
		}

		for j, n := range nodes {
			wantNode := test.want[j]

			if !n.Equal(wantNode) {
				t.Errorf("Test case: %d failed, node index: %d. %v != %v", testNo, j, n, wantNode)
			}

		}
	}

}

func nodeTestPseudorandomSlice(seed int64, size int) []byte {
	rand.Seed(seed)

	b := make([]byte, size)
	n, err := rand.Read(b)
	if n != size {
		panic(fmt.Errorf("n=%d != size=%d", n, size))
	}

	if err != nil {
		panic(err)
	}

	return b
}
