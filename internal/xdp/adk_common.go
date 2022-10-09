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

	OpenSPANot             uint64
	OpenSPAADKProofInvalid uint64
	OpenSPAADKProofValid   uint64
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

func (s Stats) Merge(u Stats) Stats {
	out := s

	if u.XDPAborted.Packets > 0 {
		out.XDPAborted.Packets = u.XDPAborted.Packets
	}

	if u.XDPAborted.Bytes > 0 {
		out.XDPAborted.Bytes = u.XDPAborted.Bytes
	}

	if u.XDPDrop.Packets > 0 {
		out.XDPDrop.Packets = u.XDPDrop.Packets
	}

	if u.XDPDrop.Bytes > 0 {
		out.XDPDrop.Bytes = u.XDPDrop.Bytes
	}

	if u.XDPPass.Packets > 0 {
		out.XDPPass.Packets = u.XDPPass.Packets
	}

	if u.XDPPass.Bytes > 0 {
		out.XDPPass.Bytes = u.XDPPass.Bytes
	}

	if u.XDPTX.Packets > 0 {
		out.XDPTX.Packets = u.XDPTX.Packets
	}

	if u.XDPTX.Bytes > 0 {
		out.XDPTX.Bytes = u.XDPTX.Bytes
	}

	if u.XDPRedirect.Packets > 0 {
		out.XDPRedirect.Packets = u.XDPRedirect.Packets
	}

	if u.XDPRedirect.Bytes > 0 {
		out.XDPRedirect.Bytes = u.XDPRedirect.Bytes
	}

	if u.OpenSPANot > 0 {
		out.OpenSPANot = u.OpenSPANot
	}

	if u.OpenSPAADKProofInvalid > 0 {
		out.OpenSPAADKProofInvalid = u.OpenSPAADKProofInvalid
	}

	if u.OpenSPAADKProofValid > 0 {
		out.OpenSPAADKProofValid = u.OpenSPAADKProofValid
	}

	return out
}
