package observability

var _ MetricsRepository = MetricsRepositoryStub{}

type MetricsRepositoryStub struct {
	CountRegistryStub
	GaugeRegistryStub
}

var _ CountRegistry = CountRegistryStub{}

type CountRegistryStub struct{}

func (_ CountRegistryStub) Count(_ string, _ Labels) Counter {
	return CounterStub{}
}

func (_ CountRegistryStub) CountVec(_ string, _ ...string) CounterVec {
	return CounterVecStub{}
}

func (_ CountRegistryStub) CountFunc(_ string, _ Labels) CounterFunc {
	return CounterFuncStub{}
}

type GaugeRegistryStub struct{}

func (_ GaugeRegistryStub) Gauge(_ string, _ Labels) Gauge {
	return GaugeStub{}
}

func (_ GaugeRegistryStub) GaugeFunc(_ string, _ Labels) GaugeFunc {
	return GaugeFuncStub{}
}

type CounterStub struct{}

func (_ CounterStub) Inc() {}

func (_ CounterStub) Add(_ int) {}

type CounterVecStub struct{}

func (_ CounterVecStub) Inc(_ ...string) {}

func (_ CounterVecStub) Add(_ int, _ ...string) {}

type CounterFuncStub struct{}

func (_ CounterFuncStub) CounterFuncRegister(_ func() float64) {}

func (_ CounterFuncStub) CounterFuncDeregister() {}

type GaugeStub struct{}

func (_ GaugeStub) Set(_ float64) {}

type GaugeFuncStub struct{}

func (_ GaugeFuncStub) GaugeFuncRegister(_ func() float64) {}

func (_ GaugeFuncStub) GaugeFuncDeregister() {}
