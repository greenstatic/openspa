package observability

var _ MetricsRepository = MetricsRepositoryStub{}

type MetricsRepositoryStub struct {
	CountRegistryStub
	GaugeRegistryStub
}

var _ CountRegistry = CountRegistryStub{}

type CountRegistryStub struct{}

func (c CountRegistryStub) Count(_ string, _ Labels) Counter {
	cs := CounterStub(0)
	return &cs
}

func (c CountRegistryStub) CountVec(_ string, _ ...string) CounterVec {
	return CounterVecStub{}
}

func (c CountRegistryStub) CountFunc(_ string, _ Labels) CounterFunc {
	return CounterFuncStub{}
}

type GaugeRegistryStub struct{}

func (g GaugeRegistryStub) Gauge(_ string, _ Labels) Gauge {
	return GaugeStub{}
}

func (g GaugeRegistryStub) GaugeFunc(_ string, _ Labels) GaugeFunc {
	return GaugeFuncStub{}
}

type CounterStub int

func (c *CounterStub) Inc() {
	*c++
}

func (c *CounterStub) Add(i int) {
	*c += CounterStub(i)
}

func (c *CounterStub) Get() int {
	return int(*c)
}

type CounterVecStub struct{}

func (c CounterVecStub) Inc(_ ...string) {}

func (c CounterVecStub) Add(_ int, _ ...string) {}

type CounterFuncStub struct{}

func (c CounterFuncStub) CounterFuncRegister(_ func() float64) {}

func (c CounterFuncStub) CounterFuncDeregister() {}

type GaugeStub struct{}

func (g GaugeStub) Set(_ float64) {}

type GaugeFuncStub struct{}

func (g GaugeFuncStub) GaugeFuncRegister(_ func() float64) {}

func (g GaugeFuncStub) GaugeFuncDeregister() {}
