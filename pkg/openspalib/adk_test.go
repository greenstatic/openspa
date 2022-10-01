package openspalib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestADKGenerateSecret(t *testing.T) {
	assert.Equal(t, 4, ADKLength)

	for i := 0; i < 100; i++ {
		k, err := ADKGenerateSecret()
		require.NoErrorf(t, err, "Iteration %d", i)
		require.Lenf(t, k, ADKSecretEncodedLen, "Iteration %d", i)
	}
}

func TestADKGenerateProof(t *testing.T) {
	s, err := ADKGenerateSecret()
	assert.NoError(t, err)

	proof0, err := ADKGenerateProof(s)
	assert.NoError(t, err)
	assert.NotEqual(t, uint32(0), proof0)

	for i := 0; i < 10; i++ {
		proof, err := ADKGenerateProof(s)
		assert.NoError(t, err)
		assert.Equal(t, proof0, proof)
	}
}

func TestADKProver(t *testing.T) {
	s, err := ADKGenerateSecret()
	assert.NoError(t, err)

	pc, err := NewADKProver(s)
	assert.NoError(t, err)

	proof0, err := pc.Proof()
	assert.NoError(t, err)
	assert.NotEqual(t, uint32(0), proof0)
	assert.NotEqualf(t, time.Time{}, pc.last, "time field last was not updated")

	for i := 0; i < 10; i++ {
		proof, err := pc.Proof()
		assert.NoError(t, err)
		assert.Equal(t, proof0, proof)
	}
}

func TestADKProver_ShouldBeFasterThanWithoutCache(t *testing.T) {
	s, err := ADKGenerateSecret()
	assert.NoError(t, err)

	pc, err := NewADKProver(s)
	assert.NoError(t, err)

	const iter = 500

	tNCStart := time.Now()

	for i := 0; i < iter; i++ {
		_, _ = ADKGenerateProof(s)
	}
	tNCEnd := time.Now()

	tNCDur := tNCEnd.Sub(tNCStart)

	tCStart := time.Now()
	for i := 0; i < iter; i++ {
		_, _ = pc.Proof()
	}
	tCEnd := time.Now()
	tCDur := tCEnd.Sub(tCStart)

	assert.Truef(t, tCDur*2 < tNCDur, "with cache should be at least twice as fast as no cache")
}

func TestADKProver_Valid(t *testing.T) {
	s, err := ADKGenerateSecret()
	assert.NoError(t, err)

	pc, err := NewADKProver(s)
	assert.NoError(t, err)

	proof, err := ADKGenerateProof(s)
	assert.NoError(t, err)
	assert.NoError(t, pc.Valid(proof))
}

func BenchmarkADKGenerateProof(b *testing.B) {
	s, err := ADKGenerateSecret()
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = ADKGenerateProof(s)
	}
}

func BenchmarkADKProver(b *testing.B) {
	s, err := ADKGenerateSecret()
	assert.NoError(b, err)

	pc, err := NewADKProver(s)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = pc.Proof()
	}
}
