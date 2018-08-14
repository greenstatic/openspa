package firewalltracker

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"time"
)

func (s *State) AddHost(connId string, h Host) error {

	s.mux.Lock()
	if !s.AcceptNewConnections {
		return errors.New("not accepting new connections")
	}
	s.mux.Unlock()

	// Attempt to extend the duration in case the host exists
	existingConnId, err := s.ExtendDurationForHost(h)
	if err == nil {
		// We extended an existing connection
		log.WithFields(log.Fields{
			"connectionId": existingConnId,
			"newDuration":  h.Duration,
		}).
			Debug("Found existing connection for host and extended the duration")
		return nil
	}

	// Looks like this is a new host connection
	if err := s.TriggerAddition.TriggerAddition(connId, h); err != nil {
		log.WithField("connectionId", connId).
			Debug("Failed to trigger addition, we are throwing away the connection")
		return err
	}

	// After the duration run the RemoveHost function on the connection
	expTrig := func() {
		s.RemoveHost(connId, h, true)
	}
	timer := time.AfterFunc(time.Duration(h.Duration)*time.Second, expTrig)

	conn := Connection{
		h,
		timer,
		[]DurationExtension{},
	}

	s.mux.Lock()

	log.WithFields(log.Fields{
		"connectionId":   connId,
		"clientDeviceId": h.ClientDeviceID,
		"protocol":       h.Protocol,
		"startPort":      h.StartPort,
		"endPort":        h.EndPort,
		"serverIp":       h.ServerIP,
		"clientIp":       h.ClientIP,
		"behindNAT":      h.BehindNAT,
	}).Debug("Creating host connection entry in firewall state management")

	s.Connections[connId] = &conn
	s.mux.Unlock()

	return nil
}

// Prolongs the timer for a host if a connection exists and return
// its connectionId otherwise throw an error.
func (s *State) ExtendDurationForHost(h Host) (connId string, err error) {

	s.mux.Lock()
	defer s.mux.Unlock()

	connId = ""

	for cId, conn := range s.Connections {
		if conn.Host.ClientDeviceID == h.ClientDeviceID &&
			conn.Host.Protocol == h.Protocol &&
			conn.Host.StartPort == h.StartPort &&
			conn.Host.EndPort == h.EndPort &&
			conn.Host.ClientIP.Equal(h.ClientIP) &&
			conn.Host.ServerIP.Equal(h.ServerIP) &&
			conn.Host.BehindNAT == h.BehindNAT {

			// Found an existing connection!
			connId = cId
			break
		}
	}

	if connId == "" {
		return connId, errors.New("no existing connections for this host configuration")
	}

	// Okay since we found an existing connection stop the timer and extend
	// it with the new duration

	// Reset timer
	timer := s.Connections[connId].Timer
	if !timer.Stop() {
		<-timer.C
	}
	timer.Reset(time.Duration(h.Duration) * time.Second)

	// Create a duration extension struct to add to the connection
	durExt := DurationExtension{
		time.Now(),
		h.Duration,
	}

	s.Connections[connId].DurationExtensions = append(s.Connections[connId].DurationExtensions, durExt)
	return connId, nil
}

// Removes a host connection. In case the triggerExpiration method
// fails, we will mark the connection as stuck. The lock should be
// always true, it is set to false only when used in the shutdown
// SignalReceiver so that it mass shutdowns all connections. The
// reasoning was since we have the lock the mutex in the function
// we cannot call the RemoveHost function since it will wait for
// the mutex to unlock. This admittedly is a terrible solution
// and the entire firewall tracker system would need to be refactored
// to support a more clean channel centric solution.
// TODO - refactor firewall tracker package to use channels instead of mutexes.
func (s *State) RemoveHost(connId string, h Host, lock bool) error {

	err := s.TriggerExpiration.TriggerExpiration(connId, h)

	if lock {
		s.mux.Lock()
		defer s.mux.Unlock()
	}

	conn, ok := s.Connections[connId]
	if !ok {
		// In case we have a non existing connection when we do not
		// accept any new connections, do not treat it as an error.
		// This could be a timer that triggered the RemoveHost function
		// while the shutdown SignalReceiver function was running - thus
		// when it finds that the host no longer exists returns an unnecessary
		// error.
		if !s.AcceptNewConnections {
			return nil
		}

		log.WithField("connectionId", connId).Warning("Could not find connectionId in the connections")
		return errors.New("non-existing connectionId")
	}
	durExt := conn.DurationExtensions

	if err != nil {
		// Mark as stuck
		log.WithFields(log.Fields{
			"connectionId":   connId,
			"clientDeviceId": h.ClientDeviceID,
			"protocol":       h.Protocol,
			"startPort":      h.StartPort,
			"endPort":        h.EndPort,
			"serverIp":       h.ServerIP,
			"clientIp":       h.ClientIP,
			"behindNAT":      h.BehindNAT,
		}).Warning("Stuck connection")

		delete(s.Connections, connId)
		s.StuckConnections = append(s.StuckConnections,
			StuckConnection{connId, h, durExt, time.Now()})
		return err
	}

	s.History = append(s.History, HostHistory{connId, h, time.Now(), durExt})
	log.WithFields(log.Fields{
		"connectionId":   connId,
		"clientDeviceId": h.ClientDeviceID,
		"protocol":       h.Protocol,
		"startPort":      h.StartPort,
		"endPort":        h.EndPort,
		"serverIp":       h.ServerIP,
		"clientIp":       h.ClientIP,
		"behindNAT":      h.BehindNAT,
		"noExtensions":   len(durExt),
	}).Info("Removing host connection")
	delete(s.Connections, connId)

	return nil
}

func (s *State) ListStuck() []StuckConnection {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.StuckConnections
}

func (s *State) PrintHistory() {
	s.mux.Lock()

	for _, hostHis := range s.History {
		fmt.Printf("Revoked: %s, connectionId: %s, clientId: %s, clientIp: %s\n",
			hostHis.Revoked.String(), hostHis.ConnectionID, hostHis.Host.ClientDeviceID,
			hostHis.Host.ClientIP.String())
	}

	s.mux.Unlock()
}
