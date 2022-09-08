package internal

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationStrategySimple(t *testing.T) {
	c := tlv.NewContainerMock()

	dur := time.Hour
	as := NewAuthorizationStrategyAllow(dur)

	d, err := as.RequestAuthorization(c)
	assert.NoError(t, err)
	assert.Equal(t, dur, d)

	c.AssertExpectations(t)
}

func TestAuthorizationStrategyCommand(t *testing.T) {
	c, err := lib.RequestDataToContainer(lib.RequestData{
		TransactionID:   0,
		ClientUUID:      "0561e333-9428-429c-8ab0-1106dd6e311c",
		ClientIP:        net.IPv4(88, 200, 23, 22).To4(),
		TargetProtocol:  lib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 23).To4(),
		TargetPortStart: 80,
		TargetPortEnd:   1000,
	}, lib.RequestExtendedData{
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	input := AuthorizationStrategyCommandAuthorizeInput{
		ClientUUID:      "0561e333-9428-429c-8ab0-1106dd6e311c",
		ClientIP:        net.IPv4(88, 200, 23, 22).To4(),
		TargetProtocol:  "TCP",
		TargetIP:        net.IPv4(88, 200, 23, 23).To4(),
		TargetPortStart: 80,
		TargetPortEnd:   1000,
	}

	inputB, err := json.Marshal(input)
	require.NoError(t, err)

	exec := &CommandExecuteMock{}

	out := AuthorizationStrategyCommandAuthorizeOutput{
		Duration: 60, // seconds
	}

	stdout, err := json.Marshal(out)
	require.NoError(t, err)

	exec.On("Execute", "foo", inputB, []string(nil)).Return(stdout, nil).Once()

	as := NewAuthorizationStrategyCommand("foo")
	as.exec = exec

	d, err := as.RequestAuthorization(c)
	assert.NoError(t, err)
	assert.Equal(t, time.Minute, d)

	exec.AssertExpectations(t)

	exec.On("Execute", "foo", inputB, []string(nil)).Return([]byte{}, errors.New("test error")).Once()

	_, err = as.RequestAuthorization(c)
	assert.Error(t, err)

	exec.AssertExpectations(t)
}

func TestAuthorizationStrategyCommand_AuthorizeInputGenerate(t *testing.T) {
	c, err := lib.RequestDataToContainer(lib.RequestData{
		TransactionID:   0,
		ClientUUID:      "0561e333-9428-429c-8ab0-1106dd6e311c",
		ClientIP:        net.IPv4(88, 200, 23, 22).To4(),
		TargetProtocol:  lib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 23).To4(),
		TargetPortStart: 80,
		TargetPortEnd:   1000,
	}, lib.RequestExtendedData{
		Timestamp: time.Now(),
	})
	require.NoError(t, err)

	inputExpect := AuthorizationStrategyCommandAuthorizeInput{
		ClientUUID:      "0561e333-9428-429c-8ab0-1106dd6e311c",
		IPIsIPv6:        false,
		ClientIP:        net.IPv4(88, 200, 23, 22).To4(),
		TargetIP:        net.IPv4(88, 200, 23, 23).To4(),
		TargetProtocol:  FirewallProtoTCP,
		TargetPortStart: 80,
		TargetPortEnd:   1000,
	}

	as := AuthorizationStrategyCommand{}
	input, err := as.authorizeInputGenerate(c)
	assert.NoError(t, err)
	assert.Equal(t, inputExpect, input)
}
