package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaddingPKCS7(t *testing.T) {
	blockSize := 16 // bytes
	rnd := make([]byte, blockSize)
	n, err := rand.Read(rnd)
	assert.NoError(t, err)
	assert.Equal(t, blockSize, n)

	for dLen := 1; dLen < 15; dLen++ {
		// Pad
		test := rnd[:dLen]
		testOut, err := PaddingPKCS7(test, blockSize)

		assert.NoError(t, err)

		for j := 0; j < dLen; j++ {
			assert.Equal(t, rnd[j], testOut[j])
		}

		assert.Len(t, testOut, blockSize)

		for i := dLen; i < len(testOut); i++ {
			assert.Equal(t, byte(blockSize-dLen), testOut[i])
		}

		// Remove Padding
		removedPadding, err := PaddingPKCS7Remove(testOut, blockSize)
		assert.NoError(t, err)
		assert.Equal(t, test, removedPadding)
	}

	// Test if no padding is required, the padded output is 2 block sizes.
	testOut, err := PaddingPKCS7(rnd, blockSize)
	assert.NoError(t, err)
	require.Len(t, testOut, blockSize*2)

	for i := 0; i < blockSize; i++ {
		assert.Equal(t, rnd[i], testOut[i])
	}

	for i := 0; i < blockSize; i++ {
		assert.Equal(t, byte(blockSize), testOut[blockSize+i])
	}

	// Remove Padding
	removedPadding, err := PaddingPKCS7Remove(testOut, blockSize)
	assert.NoError(t, err)
	assert.Equal(t, rnd, removedPadding)
}

func TestPaddingPKCS7_EmptySlice(t *testing.T) {
	blockSize := 16 // bytes
	expect := []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}

	res, err := PaddingPKCS7([]byte{}, blockSize)
	assert.NoError(t, err)
	assert.Equal(t, expect, res)
}

func TestPaddingPKCS7Remove_IncorrectPaddingValue(t *testing.T) {
	blockSize := 16 // bytes
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 2}
	assert.Len(t, d, blockSize)

	res, err := PaddingPKCS7Remove(d, blockSize)
	assert.Nil(t, res)
	assert.Error(t, err)
}

func TestPaddingPKCS7Remove_PaddingValueOutOfRange(t *testing.T) {
	blockSize := 16 // bytes
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17}
	assert.Len(t, d, blockSize)

	res, err := PaddingPKCS7Remove(d, blockSize)
	assert.Nil(t, res)
	assert.Error(t, err)
}

func TestPaddingPKCS7Remove_PaddingEmptySlice(t *testing.T) {
	blockSize := 16 // bytes
	d := []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}
	assert.Len(t, d, blockSize)

	res, err := PaddingPKCS7Remove(d, blockSize)
	assert.Len(t, res, 0)
	assert.NoError(t, err)
}
