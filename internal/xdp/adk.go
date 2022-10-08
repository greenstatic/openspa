//go:build xdp

package xdp

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func IsSupported() bool {
	return true
}

type adk struct {
	settings  ADKSettings
	proof     ADKProofGenerator
	proofSync *adkProofSynchronize

	iface netlink.Link
	flags int
	objs  bpfObjects
}

func NewADK(s ADKSettings, proof ADKProofGenerator) (ADK, error) {
	a := &adk{
		settings: s,
		proof:    proof,
	}
	a.proofSync = newADKProofSynchronize(a, proof, 20*time.Second)

	var err error

	a.iface, err = netlink.LinkByName(s.InterfaceName)
	if err != nil {
		return nil, errors.Wrap(err, "interface lookup")
	}

	return a, nil
}

func (a *adk) Start() error {
	if err := a.load(); err != nil {
		return errors.Wrap(err, "load")
	}

	if err := a.configMapSetup(); err != nil {
		_ = a.unload()
		return errors.Wrap(err, "setup config map")
	}

	if err := a.link(); err != nil {
		_ = a.unload()
		return errors.Wrap(err, "unlink")
	}

	a.proofSync.Start()

	return nil
}

func (a *adk) Stop() error {
	a.closeMaps()
	a.proofSync.Stop()

	if err := a.unload(); err != nil {
		return errors.Wrap(err, "unload")
	}

	return nil
}

func (a *adk) load() error {
	if err := loadBpfObjects(&a.objs, nil); err != nil {
		return errors.Wrap(err, "loading bpf objects")
	}

	return nil
}

func (a *adk) unload() error {
	errUnlink := a.unlink()
	errObjs := a.objs.Close()

	if errUnlink != nil && errObjs != nil {
		return errors.Wrap(errors.Wrap(errObjs, "objects close"), "unlink")
	} else if errUnlink != nil {
		return errors.Wrap(errUnlink, "unlink")
	} else if errObjs != nil {
		return errors.Wrap(errObjs, "objects close")
	}

	return nil
}

func (a *adk) link() error {
	flags := a.settings.Mode.ToNetlinkConst()
	//flags := nl.XDP_FLAGS_DRV_MODE

	if !a.settings.ReplaceIfLoaded {
		// If XDP program is already linked, do not replace it.
		flags |= nl.XDP_FLAGS_UPDATE_IF_NOEXIST
	}

	a.flags = flags

	if err := netlink.LinkSetXdpFdWithFlags(a.iface, a.objs.XdpOpenspaAdk.FD(), flags); err != nil {
		return errors.Wrap(err, "link set xdp")
	}

	return nil
}

func (a *adk) unlink() error {
	if err := netlink.LinkSetXdpFdWithFlags(a.iface, -1, a.flags); err != nil {
		return errors.Wrap(err, "link uset xdp")
	}

	return nil
}

const (
	configMapKeyServerPort uint32 = iota
	configMapKeyADKProof0
	configMapKeyADKProof1
)

func (a *adk) configMapSetup() error {
	//if err := a.objs.XdpConfigMap.Put(configMapKeyServerPort, uint32MapValue(uint32(a.settings.UDPServerPort))); err != nil {
	if err := a.objs.XdpConfigMap.Put(configMapKeyServerPort, uint32(a.settings.UDPServerPort)); err != nil {
		return errors.New("server port")
	}

	if err := a.setADKProof(a.proof); err != nil {
		return errors.Wrap(err, "adk proof")
	}

	return nil
}

func (a *adk) setADKProof(g ADKProofGenerator) error {
	proof0 := g.ADKProofNow()
	if proof0 == 0 {
		return errors.New("proof0 length invalid")
	}

	if err := a.objs.XdpConfigMap.Put(configMapKeyADKProof0, proof0); err != nil {
		return errors.Wrap(err, "proof0 put")
	}

	proof1 := g.ADKProofNext()
	if proof1 == 0 {
		return errors.New("proof1 length invalid")
	}

	if err := a.objs.XdpConfigMap.Put(configMapKeyADKProof1, proof1); err != nil {
		return errors.Wrap(err, "proof1 put")
	}

	return nil
}

func (a *adk) closeMaps() {
	a.objs.XdpConfigMap.Close()
	a.objs.XdpStatsMap.Close()
}

func (a *adk) Stats() (Stats, error) {
	return a.statsFromXDPStatsMap(a.objs.XdpStatsMap)
}

func (a *adk) statsFromXDPStatsMap(m *ebpf.Map) (Stats, error) {
	s := Stats{}
	key := make([]byte, 4)
	var val []bpfStatsDatarec

	NativeOrder.PutUint32(key, ActionAborted.Uint32())
	if err := m.Lookup(&key, &val); err != nil {
		return Stats{}, errors.Wrap(err, "lookup action aborted")
	}

	s.XDPAborted = bpfStatsDatarecSliceToStatRecord(val)

	NativeOrder.PutUint32(key, ActionDrop.Uint32())
	if err := m.Lookup(&key, &val); err != nil {
		return Stats{}, errors.Wrap(err, "lookup action aborted")
	}

	s.XDPDrop = bpfStatsDatarecSliceToStatRecord(val)

	NativeOrder.PutUint32(key, ActionPass.Uint32())
	if err := m.Lookup(&key, &val); err != nil {
		return Stats{}, errors.Wrap(err, "lookup action aborted")
	}

	s.XDPPass = bpfStatsDatarecSliceToStatRecord(val)

	NativeOrder.PutUint32(key, ActionTX.Uint32())
	if err := m.Lookup(&key, &val); err != nil {
		return Stats{}, errors.Wrap(err, "lookup action aborted")
	}

	s.XDPTX = bpfStatsDatarecSliceToStatRecord(val)

	NativeOrder.PutUint32(key, ActionRedirect.Uint32())
	if err := m.Lookup(&key, &val); err != nil {
		return Stats{}, errors.Wrap(err, "lookup action aborted")
	}

	s.XDPRedirect = bpfStatsDatarecSliceToStatRecord(val)

	return s, nil
}

func bpfStatsDatarecSliceToStatRecord(b []bpfStatsDatarec) StatsRecord {
	s := StatsRecord{}

	for _, r := range b {
		s.Bytes += r.RxBytes
		s.Packets += r.RxPackets
	}

	return s
}

func (m Mode) ToNetlinkConst() int {
	switch m {
	case ModeSKB:
		return nl.XDP_FLAGS_SKB_MODE
	case ModeDriver:
		return nl.XDP_FLAGS_DRV_MODE
	default:
		return -1
	}
}
