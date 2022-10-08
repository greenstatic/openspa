package internal

import (
	"testing"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/greenstatic/openspa/internal/xdp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestXDPADKMetrics(t *testing.T) {
	m := &statsProviderMock{}
	repo := newRepoCounterFuncStub()

	x := newXDPADKMetrics(m)
	x.mr = repo

	assert.Equal(t, 0, repo.noRegistered())

	const noMetrics = 10
	// The values should be incremented by one according to the metricNames. This helps us
	// test all of these values in a for loop by using the variable mStatsRecordValue which gets incremented by one
	// hence the requirement for these values to be incremented by one.
	mStats := xdp.Stats{
		XDPAborted:  xdp.StatsRecord{Packets: 1, Bytes: 2},
		XDPDrop:     xdp.StatsRecord{Packets: 3, Bytes: 4},
		XDPPass:     xdp.StatsRecord{Packets: 5, Bytes: 6},
		XDPTX:       xdp.StatsRecord{Packets: 7, Bytes: 8},
		XDPRedirect: xdp.StatsRecord{Packets: 9, Bytes: 10},
	}

	m.On("Stats").Return(mStats, nil)

	x.setupMetrics()
	assert.Equal(t, noMetrics, repo.noRegistered())

	metricNames := []string{
		"xdp_aborted_packets",
		"xdp_aborted_bytes",
		"xdp_drop_packets",
		"xdp_drop_bytes",
		"xdp_pass_packets",
		"xdp_pass_bytes",
		"xdp_tx_packets",
		"xdp_tx_bytes",
		"xdp_redirect_packets",
		"xdp_redirect_bytes",
	}

	mStatsRecordValue := 1

	for _, name := range metricNames {
		f := repo.getCountFuncStub(name)
		assert.NotNil(t, f, name)
		assert.Equalf(t, float64(mStatsRecordValue), f.fn(), name)
		mStatsRecordValue++
	}

	x.teardownMetrics()
	assert.Equal(t, 0, repo.noRegistered())

	m.AssertExpectations(t)
	m.AssertNumberOfCalls(t, "Stats", 1)
}

type statsProviderMock struct {
	mock.Mock
}

func (s *statsProviderMock) Stats() (xdp.Stats, error) {
	args := s.Called()
	return args.Get(0).(xdp.Stats), args.Error(1)
}

type repoCounterFuncStub struct {
	observability.MetricsRepositoryStub
	counters map[string]*counterFuncStub
}

type counterFuncStub struct {
	name          string
	lbl           observability.Labels
	fn            func() float64
	wasRegistered bool
}

var _ observability.MetricsRepository = &repoCounterFuncStub{}

func newRepoCounterFuncStub() *repoCounterFuncStub {
	r := &repoCounterFuncStub{
		counters: make(map[string]*counterFuncStub),
	}
	return r
}

func (r *repoCounterFuncStub) getCountFuncStub(name string) *counterFuncStub {
	c, ok := r.counters[name]
	if !ok {
		return nil
	}
	return c
}

func (r *repoCounterFuncStub) CountFunc(name string, l observability.Labels) observability.CounterFunc {
	c := &counterFuncStub{
		name: name,
		lbl:  l,
	}
	r.counters[name] = c
	return c
}

func (r *repoCounterFuncStub) noRegistered() int {
	count := 0

	for _, cf := range r.counters {
		if cf.isRegistered() {
			count++
		}
	}

	return count
}

var _ observability.CounterFunc = &counterFuncStub{}

func (c *counterFuncStub) CounterFuncRegister(fn func() float64) {
	c.fn = fn
	c.wasRegistered = true
}

func (c *counterFuncStub) CounterFuncDeregister() {
	c.fn = nil
}

func (c *counterFuncStub) isRegistered() bool {
	return c.fn != nil
}
