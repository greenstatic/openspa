package firewalltracker

import (
	"net"
	"sync"
	"time"
)

type State struct {
	mux                  sync.Mutex
	Connections          map[string]*Connection
	AcceptNewConnections bool
	TriggerAddition      AdditionTrigger
	TriggerExpiration    ExpirationTrigger
	History              []HostHistory
	StuckConnections     []StuckConnection
}

type Connection struct {
	Host               Host
	Timer              *time.Timer
	DurationExtensions []DurationExtension
}

type Host struct {
	ClientDeviceID string
	ClientIP       net.IP
	ServerIP       net.IP
	Protocol       string
	StartPort      int
	EndPort        int
	BehindNAT      bool
	Date           time.Time // when we created the host
	Duration       int       // original duration in seconds
}

type DurationExtension struct {
	Extended time.Time
	Duration int
}

type HostHistory struct {
	ConnectionID       string
	Host               Host
	Revoked            time.Time
	DurationExtensions []DurationExtension
}

type StuckConnection struct {
	ConnectionID      string
	Host              Host
	DurationExtension []DurationExtension
	Since             time.Time
}

type ExpirationTrigger interface {
	TriggerExpiration(string, Host) error
}

type AdditionTrigger interface {
	TriggerAddition(string, Host) error
}

func Create(addTrig AdditionTrigger, expTrig ExpirationTrigger) *State {
	conns := make(map[string]*Connection)

	return &State{
		sync.Mutex{},
		conns,
		true,
		addTrig,
		expTrig,
		make([]HostHistory, 0),
		make([]StuckConnection, 0),
	}
}
