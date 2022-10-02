package metrics

import (
	"fmt"
	"sync"
	"testing"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dto "github.com/prometheus/client_model/go"
)

func TestPrometheusRepository_WithRuntimeCollector(t *testing.T) {
	repoWithout := NewPrometheusRepository(false)
	g, err := repoWithout.reg.Gather()
	assert.NoError(t, err)
	assert.Equal(t, 0, len(g))

	repoWith := NewPrometheusRepository(true)
	g, err = repoWith.reg.Gather()
	assert.NoError(t, err)
	assert.Greater(t, len(g), 0)
}

func TestPrometheusRepositoryCount_ShouldReturnSameEntityOnSameLabel(t *testing.T) {
	repo := NewPrometheusRepository(false)

	c1 := repo.Count("foo", observability.NewLabels().Add("state", "success"))
	c2 := repo.Count("foo", observability.NewLabels().Add("state", "success"))
	c3 := repo.Count("foo", observability.NewLabels().Add("state", "failure"))

	assert.Equal(t, c1, c2)
	assert.NotEqual(t, c1, c3)
}

func TestPrometheusRepositoryCountVec_ShouldReturnSameEntityEvenOnDifferentLabelKeys(t *testing.T) {
	repo := NewPrometheusRepository(false)

	c1 := repo.CountVec("foo", "state")
	c2 := repo.CountVec("foo", "state")
	c3 := repo.CountVec("foo", "bar")

	assert.Equal(t, c1, c2)
	assert.Equal(t, c1, c3)
}

func TestPrometheusRepositoryCountFunc_ShouldReturnSameEntityOnSameLabel(t *testing.T) {
	repo := NewPrometheusRepository(false)

	c1 := repo.CountFunc("foo", observability.NewLabels().Add("state", "success"))
	c2 := repo.CountFunc("foo", observability.NewLabels().Add("state", "success"))
	c3 := repo.CountFunc("foo", observability.NewLabels().Add("state", "failure"))

	assert.Equal(t, c1, c2)
	assert.NotEqual(t, c1, c3)
}

func TestPrometheusRepositoryGauge_ShouldReturnSameEntityOnSameLabel(t *testing.T) {
	repo := NewPrometheusRepository(false)

	c1 := repo.Gauge("foo", observability.NewLabels().Add("state", "success"))
	c2 := repo.Gauge("foo", observability.NewLabels().Add("state", "success"))
	c3 := repo.Gauge("foo", observability.NewLabels().Add("state", "failure"))

	assert.Equal(t, c1, c2)
	assert.NotEqual(t, c1, c3)
}

func TestPrometheusRepositoryGaugeFunc_ShouldReturnSameEntityOnSameLabel(t *testing.T) {
	repo := NewPrometheusRepository(false)

	c1 := repo.GaugeFunc("foo", observability.NewLabels().Add("state", "success"))
	c2 := repo.GaugeFunc("foo", observability.NewLabels().Add("state", "success"))
	c3 := repo.GaugeFunc("foo", observability.NewLabels().Add("state", "failure"))

	assert.Equal(t, c1, c2)
	assert.NotEqual(t, c1, c3)
}

func TestPrometheusRepository_Handler(t *testing.T) {
	repo := NewPrometheusRepository(false)

	h := repo.Handler()
	require.NotNil(t, h)

	assert.IsType(t, promhttp.Handler(), h)
}

func TestPrometheusRepository_PanicOnWrongCounterTypeCall(t *testing.T) {
	repo := NewPrometheusRepository(false)
	str := "failed to type assert"

	repo.Count("foo", nil)
	assert.PanicsWithError(t, str, func() {
		repo.CountFunc("foo", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountVec("foo")
	})
	assert.PanicsWithError(t, str, func() {
		repo.Gauge("foo", nil)
	})

	repo.CountFunc("bar", nil)
	assert.PanicsWithError(t, str, func() {
		repo.Count("bar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountVec("bar")
	})
	assert.PanicsWithError(t, str, func() {
		repo.Gauge("bar", nil)
	})

	repo.CountVec("zar")
	assert.PanicsWithError(t, str, func() {
		repo.Count("zar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountFunc("zar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.Gauge("zar", nil)
	})

	repo.Gauge("tar", nil)
	assert.PanicsWithError(t, str, func() {
		repo.Count("tar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountVec("tar")
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountFunc("tar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.GaugeFunc("tar", nil)
	})

	repo.GaugeFunc("mar", nil)
	assert.PanicsWithError(t, str, func() {
		repo.Count("mar", nil)
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountVec("mar")
	})
	assert.PanicsWithError(t, str, func() {
		repo.CountFunc("mar", nil)
	})
}

func BenchmarkCounterUsage(b *testing.B) {
	repo := NewPrometheusRepository(false)

	_ = repo.Count("foo", map[string]string{"state": "bar"}) // save

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repo.Count("foo", map[string]string{"state": "bar"}).Inc()
	}
}

func BenchmarkSaveCounterUsage(b *testing.B) {
	repo := NewPrometheusRepository(false)

	c := repo.Count("foo", map[string]string{"state": "bar"}) // save

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Inc()
	}
}

func BenchmarkPrometheusNativeCounter(b *testing.B) {
	reg := prometheus.NewRegistry()

	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      "test",
		Help:      "",
	})
	reg.MustRegister(c)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Inc()
	}
}

func BenchmarkSaveCounterUsageWithTwoLabels(b *testing.B) {
	repo := NewPrometheusRepository(false)

	c1 := repo.Count("foo", map[string]string{"state": "bar"}) // save
	c2 := repo.Count("foo", map[string]string{"state": "zar"}) // save

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c1.Inc()
		c2.Inc()
	}
}

func BenchmarkPrometheusNativeCounterWithTwoLabelValues(b *testing.B) {
	reg := prometheus.NewRegistry()

	cv1 := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      "test",
		Help:      "",
		ConstLabels: map[string]string{
			"state": "foo",
		},
	})
	reg.MustRegister(cv1)

	cv2 := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      "test",
		Help:      "",
		ConstLabels: map[string]string{
			"state": "bar",
		},
	})
	reg.MustRegister(cv2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cv1.Inc()
		cv2.Inc()
	}
}

func BenchmarkCounterVecUsage(b *testing.B) {
	repo := NewPrometheusRepository(false)

	_ = repo.CountVec("foo", "state") // save

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repo.CountVec("foo", "state").Inc("bar")
	}
}
func BenchmarkSaveCounterVecUsage(b *testing.B) {
	repo := NewPrometheusRepository(false)

	c := repo.CountVec("foo", "state") // save

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Inc("bar")
	}
}

func BenchmarkPrometheusNativeCounterVecOneLabelValue(b *testing.B) {
	reg := prometheus.NewRegistry()

	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      "test",
		Help:      "",
	}, []string{"state"})
	reg.MustRegister(cv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cv.WithLabelValues("foo").Inc()
	}
}

func BenchmarkPrometheusNativeCounterVecTwoLabelValues(b *testing.B) {
	reg := prometheus.NewRegistry()

	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: MetricNamespace,
		Subsystem: MetricSubsystem,
		Name:      "test",
		Help:      "",
	}, []string{"state"})
	reg.MustRegister(cv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cv.WithLabelValues("foo").Inc()
		cv.WithLabelValues("bar").Inc()
	}
}

func TestCountNameKey(t *testing.T) {
	fn := []func(string, observability.Labels) string{
		countNameKey,
		countNameKeyWithForLoop,
		countNameKeyWithBuilder,
		countNameKeyWithStringsJoin,
	}
	for i, f := range fn {
		idx := fmt.Sprintf("Function index: %d", i)

		assert.Equalf(t, "foo", f("foo", nil), idx)
		assert.Equalf(t, "foo+state=bar", f("foo", map[string]string{"state": "bar"}), idx)
		assert.Equalf(t, "foo+alpha=beta+state=bar", f("foo", map[string]string{"state": "bar", "alpha": "beta"}), idx)

		// Should sort the keys
		assert.Equalf(t, "foo+alpha=beta+state=bar", f("foo", map[string]string{"alpha": "beta", "state": "bar"}), idx)
	}
}

func BenchmarkCountNameKeyWithForLoop(b *testing.B) {
	l := map[string]string{"bar": "zar"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		countNameKeyWithForLoop("foo", l)
	}
}

func BenchmarkCountNameKeyWithBuilder(b *testing.B) {
	l := map[string]string{"bar": "zar"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		countNameKeyWithBuilder("foo", l)
	}
}

func BenchmarkCountNameKeyWithStringsJoin(b *testing.B) {
	l := map[string]string{"bar": "zar"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		countNameKeyWithStringsJoin("foo", l)
	}
}

const descFoo = `Desc{fqName: "openspa_server_foo", help: "", constLabels: {}, variableLabels: []}`

func TestPrometheusCounter_Name(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounter(r, "foo", nil)

	d := c.c.Desc().String()

	assert.Equal(t, descFoo, d)
}

func TestPrometheusCounter_Labels(t *testing.T) {
	r := prometheus.NewRegistry()

	lbl := observability.NewLabels().Add("foo", "one").Add("bar", "two")
	c := NewPrometheusCounter(r, "foo", lbl)

	m := &dto.Metric{}

	assert.NoError(t, c.c.Write(m))
	assert.NotNil(t, m.Counter)

	assert.Len(t, m.Label, 2)

	// Since labels are a map we cannot rely on the order
	fooOk := false
	barOk := false

	//nolint:goconst
	for _, label := range m.Label {
		if *label.Name == "foo" && *label.Value == "one" {
			fooOk = true
		}

		if *label.Name == "bar" && *label.Value == "two" {
			barOk = true
		}
	}

	assert.True(t, fooOk)
	assert.True(t, barOk)
}

func TestPrometheusCounter_IncAndAdd(t *testing.T) {
	r := prometheus.NewRegistry()
	c := NewPrometheusCounter(r, "foo", nil)

	m := &dto.Metric{}

	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, float64(0), *m.Counter.Value)
	assert.Equal(t, 0, c.Get())

	c.Inc()
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, float64(1), *m.Counter.Value)
	assert.Equal(t, 1, c.Get())

	c.Inc()
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, float64(2), *m.Counter.Value)
	assert.Equal(t, 2, c.Get())

	c.Add(1)
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, float64(3), *m.Counter.Value)
	assert.Equal(t, 3, c.Get())

	c.Add(3)
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, float64(6), *m.Counter.Value)
	assert.Equal(t, 6, c.Get())
}

func TestPrometheusCounterVec_Name(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounterVec(r, "foo", "foo")

	m, err := c.c.MetricVec.GetMetricWith(map[string]string{"foo": ""})
	assert.NoError(t, err)

	d := m.Desc().String()
	dExp := `Desc{fqName: "openspa_server_foo", help: "", constLabels: {}, variableLabels: [foo]}`
	assert.Equal(t, dExp, d)
}

func TestPrometheusCounterVec_DifferentLabelKeys(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounterVec(r, "foo", "state")

	c.Inc("f1")
	c.Inc("f2")
	c.Inc("f2")

	fInvalid, err := c.c.MetricVec.GetMetricWith(map[string]string{"state": ""})
	assert.NoError(t, err)

	m := &dto.Metric{}
	assert.NoError(t, fInvalid.Write(m))
	require.NotNil(t, m.Counter)
	assert.Equal(t, float64(0), *m.Counter.Value)

	f1, err := c.c.MetricVec.GetMetricWith(map[string]string{"state": "f1"})
	assert.NoError(t, err)
	assert.NoError(t, f1.Write(m))
	require.NotNil(t, m.Counter)
	assert.Equal(t, float64(1), *m.Counter.Value)

	f2, err := c.c.MetricVec.GetMetricWith(map[string]string{"state": "f2"})
	assert.NoError(t, err)
	assert.NoError(t, f2.Write(m))
	require.NotNil(t, m.Counter)
	assert.Equal(t, float64(2), *m.Counter.Value)
}

func TestPrometheusCounterVec_IncAndAdd(t *testing.T) {
	r := prometheus.NewRegistry()
	c := NewPrometheusCounterVec(r, "foo", "state")

	mv, err := c.c.MetricVec.GetMetricWith(map[string]string{"state": "s1"})
	assert.NoError(t, err)

	m := &dto.Metric{}

	assert.NoError(t, mv.Write(m))
	assert.Equal(t, float64(0), *m.Counter.Value)

	c.Inc("s1")
	assert.NoError(t, mv.Write(m))
	assert.Equal(t, float64(1), *m.Counter.Value)

	c.Inc("s1")
	assert.NoError(t, mv.Write(m))
	assert.Equal(t, float64(2), *m.Counter.Value)

	c.Add(1, "s1")
	assert.NoError(t, mv.Write(m))
	assert.Equal(t, float64(3), *m.Counter.Value)

	c.Add(3, "s1")
	assert.NoError(t, mv.Write(m))
	assert.Equal(t, float64(6), *m.Counter.Value)
}

func TestPrometheusCounterFunc_Name(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounterFunc(r, "foo", nil)

	d := c.c.Desc().String()
	assert.Equal(t, descFoo, d)
}

func TestPrometheusCounterFunc_Labels(t *testing.T) {
	r := prometheus.NewRegistry()

	lbl := observability.NewLabels().Add("foo", "one").Add("bar", "two")
	c := NewPrometheusCounterFunc(r, "foo", lbl)

	m := &dto.Metric{}

	assert.NoError(t, c.c.Write(m))
	assert.NotNil(t, m.Counter)

	assert.Len(t, m.Label, 2)

	// Since labels are a map we cannot rely on the order
	fooOk := false
	barOk := false

	for _, label := range m.Label {
		if *label.Name == "foo" && *label.Value == "one" {
			fooOk = true
		}

		if *label.Name == "bar" && *label.Value == "two" {
			barOk = true
		}
	}

	assert.True(t, fooOk)
	assert.True(t, barOk)
}

func TestPrometheusCounterFunc_Register(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounterFunc(r, "foo", nil)

	called := 0

	c.CounterFuncRegister(func() float64 {
		called++
		return float64(called)
	})

	m := &dto.Metric{}
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, 1, called)

	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, 2, called)
}

func TestPrometheusCounterFunc_Deregister(t *testing.T) {
	r := prometheus.NewRegistry()

	c := NewPrometheusCounterFunc(r, "foo", nil)

	called := 0
	c.CounterFuncRegister(func() float64 {
		called++
		return float64(called)
	})

	m := &dto.Metric{}
	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, 1, called)

	c.CounterFuncDeregister()

	assert.NoError(t, c.c.Write(m))
	assert.Equal(t, 1, called) // no additional calls to the callback we registered above
	assert.Equal(t, float64(0), *m.Counter.Value)
}

func TestPrometheusGauge_Name(t *testing.T) {
	r := prometheus.NewRegistry()

	g := NewPrometheusGauge(r, "foo", nil)

	d := g.g.Desc().String()

	assert.Equal(t, descFoo, d)
}

func TestPrometheusGauge_Labels(t *testing.T) {
	r := prometheus.NewRegistry()

	lbl := observability.NewLabels().Add("foo", "one").Add("bar", "two")
	g := NewPrometheusGauge(r, "foo", lbl)

	m := &dto.Metric{}

	assert.NoError(t, g.g.Write(m))
	assert.NotNil(t, m.Gauge)

	assert.Len(t, m.Label, 2)

	// Since labels are a map we cannot rely on the order
	fooOk := false
	barOk := false

	for _, label := range m.Label {
		if *label.Name == "foo" && *label.Value == "one" {
			fooOk = true
		}

		if *label.Name == "bar" && *label.Value == "two" {
			barOk = true
		}
	}

	assert.True(t, fooOk)
	assert.True(t, barOk)
}

func TestPrometheusGauge_Set(t *testing.T) {
	r := prometheus.NewRegistry()
	g := NewPrometheusGauge(r, "foo", nil)

	m := &dto.Metric{}

	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, float64(0), *m.Gauge.Value)

	g.Set(float64(1))
	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, float64(1), *m.Gauge.Value)

	g.Set(float64(2))
	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, float64(2), *m.Gauge.Value)

	g.Set(float64(1.234))
	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, float64(1.234), *m.Gauge.Value)
}

func TestPrometheusGaugeFunc_Name(t *testing.T) {
	r := prometheus.NewRegistry()

	g := NewPrometheusGaugeFunc(r, "foo", nil)

	d := g.g.Desc().String()
	assert.Equal(t, descFoo, d)
}

func TestPrometheusGaugeFunc_Labels(t *testing.T) {
	r := prometheus.NewRegistry()

	lbl := observability.NewLabels().Add("foo", "one").Add("bar", "two")
	g := NewPrometheusGaugeFunc(r, "foo", lbl)

	m := &dto.Metric{}

	assert.NoError(t, g.g.Write(m))
	assert.NotNil(t, m.Gauge)

	assert.Len(t, m.Label, 2)

	// Since labels are a map we cannot rely on the order
	fooOk := false
	barOk := false

	for _, label := range m.Label {
		if *label.Name == "foo" && *label.Value == "one" {
			fooOk = true
		}

		if *label.Name == "bar" && *label.Value == "two" {
			barOk = true
		}
	}

	assert.True(t, fooOk)
	assert.True(t, barOk)
}

func TestPrometheusGaugeFunc_Register(t *testing.T) {
	r := prometheus.NewRegistry()

	g := NewPrometheusGaugeFunc(r, "foo", nil)

	called := 0

	g.GaugeFuncRegister(func() float64 {
		called++
		return float64(called)
	})

	m := &dto.Metric{}
	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, 1, called)

	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, 2, called)
}

func TestPrometheusGaugeFunc_Deregister(t *testing.T) {
	r := prometheus.NewRegistry()

	g := NewPrometheusGaugeFunc(r, "foo", nil)

	called := 0
	g.GaugeFuncRegister(func() float64 {
		called++
		return float64(called)
	})

	m := &dto.Metric{}
	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, 1, called)

	g.GaugeFuncDeregister()

	assert.NoError(t, g.g.Write(m))
	assert.Equal(t, 1, called) // no additional calls to the callback we registered above
	assert.Equal(t, float64(0), *m.Gauge.Value)
}

func TestPrometheusGaugeFunc_Concurrently(t *testing.T) {
	r := NewPrometheusRepository(false)

	wg := sync.WaitGroup{}
	for i := 0; i < 200_000; i++ {
		wg.Add(1)
		go func() {
			g := r.GaugeFunc("test", map[string]string{"foo": "bar"})
			g.GaugeFuncRegister(func() float64 {
				return 0
			})
			wg.Done()
		}()
	}

	wg.Wait()
}
