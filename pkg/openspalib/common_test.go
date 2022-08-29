package openspalib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPortCanBeZero(t *testing.T) {
	assert.False(t, portCanBeZero(ProtocolTCP))
	assert.False(t, portCanBeZero(ProtocolUDP))
	assert.True(t, portCanBeZero(ProtocolICMP))
	assert.True(t, portCanBeZero(ProtocolIPV4))
	assert.True(t, portCanBeZero(ProtocolICMPv6))
}
