package observability

import (
	"sync"
)

var (
	global = NewGlobalMetricsRepository(MetricsRepositoryStub{})
)

func GetGlobalMetricsRepository() MetricsRepository {
	return global.r
}

func SetGlobalMetricsRepository(mr MetricsRepository) {
	global.lock.Lock()
	defer global.lock.Unlock()

	global.r = mr
	for _, f := range global.changeCallbacks {
		f(mr)
	}
}

func OnMetricsRepositoryGlobalSet(f globalMetricsRepositoryChangeCallback) {
	global.lock.Lock()
	defer global.lock.Unlock()
	global.changeCallbacks = append(global.changeCallbacks, f)
}

type globalMetricsRepository struct {
	r MetricsRepository

	changeCallbacks []globalMetricsRepositoryChangeCallback
	lock            sync.Mutex
}

type globalMetricsRepositoryChangeCallback func(m MetricsRepository)

func NewGlobalMetricsRepository(mr MetricsRepository) *globalMetricsRepository {
	g := &globalMetricsRepository{
		r: mr,
	}
	g.changeCallbacks = make([]globalMetricsRepositoryChangeCallback, 0)
	return g
}
