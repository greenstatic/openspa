package internal

import (
	"github.com/greenstatic/openspa/internal/observability"
	"github.com/greenstatic/openspa/internal/observability/metrics"
)

var _metrics = observability.GetGlobalMetricsRepository()

var prometheusRepo *metrics.PrometheusRepository

//nolint:gochecknoinits
func init() {
	observability.OnMetricsRepositoryGlobalSet(SetMetricsRepository)

	prometheusRepo = metrics.NewPrometheusRepository(true)
	observability.SetGlobalMetricsRepository(prometheusRepo)
}

func getMetricsRepository() observability.MetricsRepository {
	return _metrics
}

func SetMetricsRepository(m observability.MetricsRepository) {
	_metrics = m
}
