package firewalltracker

import (
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

// When launched due to receiving a signal, will remove all hosts that
// are in the state firewall connection map.
func (s *State) SignalReceiver(sig chan os.Signal, shutdown chan bool) {

	signal := <-sig

	log.WithField("signal", signal).
		Info("Received signal to shut down, running shutdown script for all connections")

	// Remove every single host from the connection map
	// Deny new connections
	s.mux.Lock()
	s.AcceptNewConnections = false
	defer s.mux.Unlock()

	for cId, conn := range s.Connections {
		err := s.RemoveHost(cId, conn.Host, false) // see the RemoveHost function to see what lock:false does
		if err != nil {
			log.WithFields(log.Fields{
				"connectionId":   cId,
				"clientDeviceId": conn.Host.ClientDeviceID,
				"protocol":       conn.Host.Protocol,
				"startPort":      conn.Host.StartPort,
				"endPort":        conn.Host.EndPort,
				"serverIp":       conn.Host.ServerIP,
				"clientIp":       conn.Host.ClientIP,
				"behindNAT":      conn.Host.BehindNAT,
				"error":          err,
			}).
				Error("Failed to run remove host on shutdown, client might have permanent access rule in firewall")
			log.Error(err)
		}
		conn.Timer.Stop() // stop the triggering of the automatic removeHost since we already removed it
		log.Debug("Successfully shutdown client connection")
	}

	// Total number of unique connections
	totalUniqueConn := len(s.History)

	log.WithField("uniqueConnections", totalUniqueConn).Info("Total number of unique connections")
	time.Sleep(time.Duration(2) * time.Second) // A delay just so everything is executed properly
	shutdown <- true
}
