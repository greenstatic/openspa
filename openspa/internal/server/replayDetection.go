package server

import (
	"crypto/sha256"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/greenstatic/openspa/openspalib/request"
)

type ReplayDetect struct {
	HashedPackets map[string]bool
	mux           sync.Mutex
}

// Discard packets that were generated more than 5 min ago - first line of
// defense against replay defense
func expiredPacket(packet request.Packet) error {
	var dur time.Duration = 5 * time.Minute
	if time.Now().Sub(packet.Payload.Timestamp) > dur {
		return errors.New("packet expired")
	}

	return nil
}

func (rd *ReplayDetect) Setup() {
	rd.HashedPackets = make(map[string]bool)
}

// Checks if the packet has already been sent by taking the SHA-256 hash of
// the packet and comparing it with all the received packets.
func (rd *ReplayDetect) Check(packet []byte) error {

	if rd.HashedPackets == nil {
		log.Fatal("ReplayDetect struct was not setup using the Setup() function")
	}

	// Take hash of the packet
	sum := sha256.Sum256(packet)
	sumStr := string(sum[:])

	rd.mux.Lock()
	defer rd.mux.Unlock()
	_, found := rd.HashedPackets[sumStr]
	if found {
		return errors.New("hash of packet found")
	}

	rd.HashedPackets[sumStr] = true

	return nil
}
