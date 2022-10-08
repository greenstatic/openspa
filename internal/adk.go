package internal

import (
	"sync"
	"time"

	"github.com/greenstatic/openspa/internal/observability"
	"github.com/greenstatic/openspa/internal/xdp"
	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/pkg/errors"
)

var _ xdp.ADKProofGenerator = ADKProofGen{}

type ADKProofGen struct {
	secret string
}

func NewADKProofGen(secret string) ADKProofGen {
	return ADKProofGen{secret: secret}
}

func (a ADKProofGen) ADKProofNow() uint32 {
	proof, err := openspalib.ADKGenerateProof(a.secret)
	if err != nil {
		return 0
	}

	return proof
}

func (a ADKProofGen) ADKProofNext() uint32 {
	proof, err := openspalib.ADKGenerateNextProof(a.secret)
	if err != nil {
		return 0
	}

	return proof
}

func SetupXDPADKMetrics(sp xdp.StatsProvider, stop chan bool) {
	x := newXDPADKMetrics(sp)
	go func() {
		<-stop
		x.teardownMetrics()
	}()
}

type xdpADKMetrics struct {
	provider xdp.StatsProvider

	stats     xdp.Stats
	cached    time.Time
	cacheLock sync.Mutex

	cacheValidity time.Duration

	counterFuncs []observability.CounterFunc
	mr           observability.MetricsRepository
}

func newXDPADKMetrics(sp xdp.StatsProvider) *xdpADKMetrics {
	x := &xdpADKMetrics{
		provider:      sp,
		cacheValidity: time.Second,
		mr:            getMetricsRepository(),
	}
	return x
}

func (x *xdpADKMetrics) getStats() (xdp.Stats, error) {
	x.cacheLock.Lock()
	defer x.cacheLock.Unlock()
	validTill := x.cached.Add(x.cacheValidity)
	expired := time.Now().After(validTill)

	if expired {
		stats, err := x.provider.Stats()
		if err != nil {
			return xdp.Stats{}, errors.Wrap(err, "provider")
		}
		x.stats = stats
		x.cached = time.Now()
	}

	return x.stats, nil
}

func (x *xdpADKMetrics) setupMetrics() {
	lbl := observability.NewLabels()

	x.counterFuncs = make([]observability.CounterFunc, 0)

	var f observability.CounterFunc

	type r struct {
		name string
		f    func() float64
	}

	regs := []r{
		{name: "xdp_aborted_packets", f: x.xdpAbortedPackets},
		{name: "xdp_aborted_bytes", f: x.xdpAbortedBytes},
		{name: "xdp_drop_packets", f: x.xdpDropPackets},
		{name: "xdp_drop_bytes", f: x.xdpDropBytes},
		{name: "xdp_pass_packets", f: x.xdpPassPackets},
		{name: "xdp_pass_bytes", f: x.xdpPassBytes},
		{name: "xdp_tx_packets", f: x.xdpTXPackets},
		{name: "xdp_tx_bytes", f: x.xdpTXBytes},
		{name: "xdp_redirect_packets", f: x.xdpRedirectPackets},
		{name: "xdp_redirect_bytes", f: x.xdpRedirectBytes},
	}

	for _, reg := range regs {
		f = x.mr.CountFunc(reg.name, lbl)
		f.CounterFuncRegister(reg.f)
		x.counterFuncs = append(x.counterFuncs, f)
	}
}

func (x *xdpADKMetrics) teardownMetrics() {
	for _, count := range x.counterFuncs {
		count.CounterFuncDeregister()
	}
}

func (x *xdpADKMetrics) floatOrError(f float64, err error) float64 {
	if err != nil {
		return -1
	}
	return f
}

func (x *xdpADKMetrics) xdpAbortedPackets() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPAborted.Packets), err)
}

func (x *xdpADKMetrics) xdpAbortedBytes() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPAborted.Bytes), err)
}

func (x *xdpADKMetrics) xdpDropPackets() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPDrop.Packets), err)
}

func (x *xdpADKMetrics) xdpDropBytes() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPDrop.Bytes), err)
}

func (x *xdpADKMetrics) xdpPassPackets() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPPass.Packets), err)
}

func (x *xdpADKMetrics) xdpPassBytes() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPPass.Bytes), err)
}

func (x *xdpADKMetrics) xdpTXPackets() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPTX.Packets), err)
}

func (x *xdpADKMetrics) xdpTXBytes() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPTX.Bytes), err)
}

func (x *xdpADKMetrics) xdpRedirectPackets() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPRedirect.Packets), err)
}

func (x *xdpADKMetrics) xdpRedirectBytes() float64 {
	s, err := x.getStats()
	return x.floatOrError(float64(s.XDPRedirect.Bytes), err)
}
