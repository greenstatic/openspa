package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	MetricNamespace = "openspa"
	MetricSubsystem = "server"
)

var _ observability.MetricsRepository = &PrometheusRepository{}

// PrometheusRepository implements the observability.MetricsRepository interface.
// Counter implementation
//
//	Pros:
//	- Fast (benchmarks on development machines not end customer hardware!) shows approx. 9ns per Inc() operation
//	  if the returned Counter implementation is stored instead of calling Counter() each time.
//	Cons:
//	- Requires you to store each metric label variant
//
// CounterVec implementation
//
//	Pros:
//	- Can save a single variable for all metric label values (since we initialize only the label keys)
//	Cons:
//	- Slower than Counter (benchmarks on development machine) shows approx. 94ns per Inc() operation if the returned
//	  CounterVec implementation is stored instead of calling CounterVec() each time.
//
// CounterFunc implementation
//
//	Pros:
//	- Value can be calculated externally
//	Cons:
//	- Requires a callback to be registered (and deregistered)
type PrometheusRepository struct {
	m    map[string]metric
	lock sync.Mutex

	reg PrometheusRegistererGatherer
}

type PrometheusRegistererGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}

func NewPrometheusRepository(withRuntimeCollector bool) *PrometheusRepository {
	r := NewPrometheusRepositoryCustomRegistry(prometheus.NewRegistry())

	if withRuntimeCollector {
		r.reg.MustRegister(collectors.NewGoCollector())
	}

	return r
}

func NewPrometheusRepositoryCustomRegistry(reg PrometheusRegistererGatherer) *PrometheusRepository {
	r := &PrometheusRepository{}
	r.m = make(map[string]metric)

	r.reg = reg

	return r
}

func (r *PrometheusRepository) Handler() http.Handler {
	return promhttp.InstrumentMetricHandler(
		r.reg, promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{}),
	)
}

func (r *PrometheusRepository) Count(name string, l observability.Labels) observability.Counter {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.countGet(name, l)
}

func (r *PrometheusRepository) countGet(name string, l observability.Labels) *PrometheusCounter {
	key := countNameKey(name, l)
	m, ok := r.m[key]
	var c *PrometheusCounter
	if !ok {
		c = NewPrometheusCounter(r.reg, name, l)
		m = metric{c}
		r.m[key] = m
	} else {
		c, ok = m.m.(*PrometheusCounter)
		if !ok {
			panic(errors.New("failed to type assert"))
		}
	}

	return c
}

func (r *PrometheusRepository) CountVec(name string, labelKeys ...string) observability.CounterVec {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.countVecGet(name, labelKeys...)
}

func (r *PrometheusRepository) countVecGet(name string, labelKeys ...string) *PrometheusCounterVec {
	m, ok := r.m[name]
	var c *PrometheusCounterVec
	if !ok {
		c = NewPrometheusCounterVec(r.reg, name, labelKeys...)
		m = metric{c}
		r.m[name] = m
	} else {
		c, ok = m.m.(*PrometheusCounterVec)
		if !ok {
			panic(errors.New("failed to type assert"))
		}
	}

	return c
}

func (r *PrometheusRepository) CountFunc(name string, l observability.Labels) observability.CounterFunc {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.countFuncGet(name, l)
}

func (r *PrometheusRepository) countFuncGet(name string, l observability.Labels) *PrometheusCounterFunc {
	key := countNameKey(name, l)
	m, ok := r.m[key]
	var c *PrometheusCounterFunc
	if !ok {
		c = NewPrometheusCounterFunc(r.reg, name, l)
		m = metric{c}
		r.m[key] = m
	} else {
		c, ok = m.m.(*PrometheusCounterFunc)
		if !ok {
			panic(errors.New("failed to type assert"))
		}
	}

	return c
}

func (r *PrometheusRepository) Gauge(name string, l observability.Labels) observability.Gauge {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.gaugeGet(name, l)
}

func (r *PrometheusRepository) gaugeGet(name string, l observability.Labels) *PrometheusGauge {
	key := countNameKey(name, l)
	m, ok := r.m[key]
	var c *PrometheusGauge
	if !ok {
		c = NewPrometheusGauge(r.reg, name, l)
		m = metric{c}
		r.m[key] = m
	} else {
		c, ok = m.m.(*PrometheusGauge)
		if !ok {
			panic(errors.New("failed to type assert"))
		}
	}

	return c
}

func (r *PrometheusRepository) GaugeFunc(name string, l observability.Labels) observability.GaugeFunc {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.gaugeFuncGet(name, l)
}

func (r *PrometheusRepository) gaugeFuncGet(name string, l observability.Labels) *PrometheusGaugeFunc {
	key := countNameKey(name, l)
	m, ok := r.m[key]
	var c *PrometheusGaugeFunc
	if !ok {
		c = NewPrometheusGaugeFunc(r.reg, name, l)
		m = metric{c}
		r.m[key] = m
	} else {
		c, ok = m.m.(*PrometheusGaugeFunc)
		if !ok {
			panic(errors.New("failed to type assert"))
		}
	}

	return c
}

type metric struct {
	m interface{}
}

var _ observability.Counter = &PrometheusCounter{}

type PrometheusCounter struct {
	c prometheus.Counter
}

func NewPrometheusCounter(r prometheus.Registerer, name string, l observability.Labels) *PrometheusCounter {
	c := &PrometheusCounter{}

	c.c = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   MetricNamespace,
		Subsystem:   MetricSubsystem,
		Name:        name,
		Help:        "",
		ConstLabels: l.ToMap(),
	})

	r.MustRegister(c.c)

	return c
}

func (c PrometheusCounter) Inc() {
	c.c.Inc()
}

func (c PrometheusCounter) Add(count int) {
	c.c.Add(float64(count))
}

var _ observability.CounterVec = &PrometheusCounterVec{}

type PrometheusCounterVec struct {
	c *prometheus.CounterVec
}

func NewPrometheusCounterVec(r prometheus.Registerer, name string, labelKeys ...string) *PrometheusCounterVec {
	cv := &PrometheusCounterVec{}

	cv.c = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      name,
		Help:      "",
	}, labelKeys)

	r.MustRegister(cv.c)

	return cv
}

func (c *PrometheusCounterVec) Inc(labelValues ...string) {
	c.c.WithLabelValues(labelValues...).Inc()
}

func (c *PrometheusCounterVec) Add(count int, labelValues ...string) {
	c.c.WithLabelValues(labelValues...).Add(float64(count))
}

var _ observability.CounterFunc = &PrometheusCounterFunc{}

type PrometheusCounterFunc struct {
	c        prometheus.CounterFunc
	callback func() float64

	f func() float64
}

func NewPrometheusCounterFunc(r prometheus.Registerer, name string, l observability.Labels) *PrometheusCounterFunc {
	cf := &PrometheusCounterFunc{}
	cf.f = func() float64 {
		return cf.callback()
	}
	cf.callback = cf.defaultCallback

	cf.c = prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace:   MetricNamespace,
		Subsystem:   MetricSubsystem,
		Name:        name,
		Help:        "",
		ConstLabels: l.ToMap(),
	}, cf.f)

	r.MustRegister(cf.c)

	return cf
}

func (cf *PrometheusCounterFunc) CounterFuncRegister(fn func() float64) {
	cf.callback = fn
}

func (cf *PrometheusCounterFunc) CounterFuncDeregister() {
	cf.callback = cf.defaultCallback
}

func (cf *PrometheusCounterFunc) defaultCallback() float64 {
	return float64(0)
}

var _ observability.Gauge = &PrometheusGauge{}

type PrometheusGauge struct {
	g prometheus.Gauge
}

func NewPrometheusGauge(r prometheus.Registerer, name string, l observability.Labels) *PrometheusGauge {
	g := &PrometheusGauge{}

	g.g = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   MetricNamespace,
		Subsystem:   MetricSubsystem,
		Name:        name,
		Help:        "",
		ConstLabels: l.ToMap(),
	})

	r.MustRegister(g.g)

	return g
}

func (g PrometheusGauge) Set(f float64) {
	g.g.Set(f)
}

var _ observability.GaugeFunc = &PrometheusGaugeFunc{}

type PrometheusGaugeFunc struct {
	g        prometheus.GaugeFunc
	callback func() float64

	f func() float64
}

func NewPrometheusGaugeFunc(r prometheus.Registerer, name string, l observability.Labels) *PrometheusGaugeFunc {
	gf := &PrometheusGaugeFunc{}
	gf.f = func() float64 {
		return gf.callback()
	}
	gf.callback = gf.defaultCallback

	gf.g = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace:   MetricNamespace,
		Subsystem:   MetricSubsystem,
		Name:        name,
		Help:        "",
		ConstLabels: l.ToMap(),
	}, gf.f)

	r.MustRegister(gf.g)

	return gf
}

func (cf *PrometheusGaugeFunc) GaugeFuncRegister(fn func() float64) {
	cf.callback = fn
}

func (cf *PrometheusGaugeFunc) GaugeFuncDeregister() {
	cf.callback = cf.defaultCallback
}

func (cf *PrometheusGaugeFunc) defaultCallback() float64 {
	return float64(0)
}

func countNameKey(name string, l observability.Labels) string {
	return countNameKeyWithForLoop(name, l)
}

func countNameKeyWithForLoop(name string, l observability.Labels) string {
	s := name

	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		v := l[k]
		s += "+" + k + "=" + v
	}

	return s
}

func countNameKeyWithBuilder(name string, l observability.Labels) string {
	s := strings.Builder{}
	s.WriteString(name)

	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		v := l[k]
		s.WriteString("+")
		s.WriteString(k)
		s.WriteString("=")
		s.WriteString(v)
	}

	return s.String()
}

func countNameKeyWithStringsJoin(name string, l observability.Labels) string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	lk := make([]string, len(l))

	i := 0
	for _, k := range keys {
		v := l[k]
		lk[i] = fmt.Sprintf("%s=%s", k, v)
		i++
	}

	if len(l) == 0 {
		return name
	}

	return name + "+" + strings.Join(lk, "+")
}
