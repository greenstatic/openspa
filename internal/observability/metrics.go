package observability

type MetricsRepository interface {
	CountRegistry
	GaugeRegistry
}

type Labels map[string]string

// CountRegistry implements various Counter metrics. When choosing the Counter type, keep in mind that each Counter type
// has its pros and cons. Check the implementation's documentation for details.
type CountRegistry interface {
	Count(name string, l Labels) Counter

	// CountVec doesn't need constant labels (i.e. predefined label key(s) and value(s)), just constant label keys
	CountVec(name string, labelKeys ...string) CounterVec

	CountFunc(name string, l Labels) CounterFunc
}

type Counter interface {
	Inc()
	Add(count int)
}

type CounterVec interface {
	Inc(labelValues ...string)
	Add(count int, labelValues ...string)
}

type CounterFunc interface {
	CounterFuncRegister(fn func() float64)
	CounterFuncDeregister()
}

type GaugeRegistry interface {
	Gauge(name string, l Labels) Gauge

	GaugeFunc(name string, l Labels) GaugeFunc
}

type Gauge interface {
	Set(f float64)
}

type GaugeFunc interface {
	GaugeFuncRegister(fn func() float64)
	GaugeFuncDeregister()
}

func NewLabels() Labels {
	return make(map[string]string)
}

func (l Labels) ToMap() map[string]string {
	return l
}

// Add returns a new copy of Labels with an additional entry, the key/value this function is called with.
func (l Labels) Add(key, value string) Labels {
	m := make(map[string]string)

	for k, v := range l {
		m[k] = v
	}

	m[key] = value
	return m
}
