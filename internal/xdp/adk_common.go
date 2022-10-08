package xdp

import (
	"time"

	"github.com/rs/zerolog/log"
)

type ADK interface {
	StatsProvider
	Start() error
	Stop() error
}

type StatsProvider interface {
	Stats() (Stats, error)
}

type ADKProofGenerator interface {
	ADKProofNow() uint32
	ADKProofNext() uint32
}

const ADKProofLength = 4 // bytes

type ADKSettings struct {
	InterfaceName   string
	Mode            Mode
	ReplaceIfLoaded bool
	UDPServerPort   int
}

type Stats struct {
	XDPAborted  StatsRecord
	XDPDrop     StatsRecord
	XDPPass     StatsRecord
	XDPTX       StatsRecord
	XDPRedirect StatsRecord
}

type StatsRecord struct {
	Packets uint64
	Bytes   uint64
}

type adkProofSetter interface {
	setADKProof(g ADKProofGenerator) error
}

type adkProofSynchronize struct {
	setter    adkProofSetter
	generator ADKProofGenerator
	period    time.Duration

	quit chan bool
}

func newADKProofSynchronize(s adkProofSetter, g ADKProofGenerator, period time.Duration) *adkProofSynchronize {
	a := &adkProofSynchronize{
		setter:    s,
		generator: g,
		period:    period,
	}
	return a
}

func (a *adkProofSynchronize) Start() {
	if a.quit != nil {
		// Already running
		return
	}
	a.quit = make(chan bool)

	go a.routine(a.quit)
}

func (a *adkProofSynchronize) routine(stop chan bool) {
	t := time.NewTicker(a.period)

	a.routineEvent()
	for {
		select {
		case <-t.C:
			a.routineEvent()
		case <-stop:
			return
		}
	}
}

func (a *adkProofSynchronize) routineEvent() {
	err := a.setter.setADKProof(a.generator)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to set ADK proof in XDP")
	}
}

func (a *adkProofSynchronize) Stop() {
	if a.quit == nil {
		// Not running
		return
	}

	a.quit <- true
	a.quit = nil
}
