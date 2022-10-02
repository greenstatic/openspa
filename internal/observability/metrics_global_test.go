package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetGlobalMetricsRepository(t *testing.T) {
	mr1 := GetGlobalMetricsRepository()

	type MetricsRepositoryStub2 struct {
		MetricsRepositoryStub
	}

	mr2 := MetricsRepositoryStub2{}

	SetGlobalMetricsRepository(mr2)

	assert.NotEqual(t, mr1, GetGlobalMetricsRepository())
	assert.Equal(t, mr2, GetGlobalMetricsRepository())
}

func TestOnMetricsRepositoryGlobalSet(t *testing.T) {
	calls := 0
	var mrCallback MetricsRepository
	callback := func(mr MetricsRepository) {
		calls++
		mrCallback = mr
	}

	OnMetricsRepositoryGlobalSet(callback)
	assert.Equal(t, 0, calls)
	assert.Nil(t, mrCallback)

	type MetricsRepositoryStub2 struct {
		MetricsRepositoryStub
	}

	mr2 := MetricsRepositoryStub2{}
	SetGlobalMetricsRepository(mr2)

	assert.Equal(t, 1, calls)
	assert.NotNil(t, mrCallback)
	assert.Equal(t, mr2, mrCallback)
}
