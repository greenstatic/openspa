package xdp

type Mode uint8

const (
	ModeUndefined Mode = iota
	ModeSKB
	ModeDriver
	// ModeHW
)

func (m Mode) Valid() bool {
	//nolint:exhaustive
	switch m {
	// case ModeSKB, ModeDriver, ModeHW:
	case ModeSKB, ModeDriver:
		return true
	default:
		return false
	}
}

func ModeFromString(s string) (m Mode, ok bool) {
	switch s {
	case "skb":
		return ModeSKB, true
	case "driver":
		return ModeDriver, true
	default:
		return ModeUndefined, false
	}
}

type Action uint8

const (
	ActionAborted Action = iota
	ActionDrop
	ActionPass
	ActionTX
	ActionRedirect
)

func (x Action) String() string {
	switch x {
	case ActionAborted:
		return "XDP_ABORTED"
	case ActionDrop:
		return "XDP_DROP"
	case ActionPass:
		return "XDP_PASS"
	case ActionTX:
		return "XDP_TX"
	case ActionRedirect:
		return "XDP_REDIRECT"
	default:
		return ""
	}
}

func (x Action) Uint32() uint32 {
	return uint32(x)
}

type OSPAStatID uint8

const (
	OSPAStatIDNotOpenSPAPacket OSPAStatID = iota
	OSPAStatIDADKProofInvalid
	OSPAStatIDADKProofValid
)

func (o OSPAStatID) Uint32() uint32 {
	return uint32(o)
}
