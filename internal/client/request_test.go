package client

import (
	"crypto/rsa"
	"net"
	"testing"
	"time"

	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRequestRoutine(t *testing.T) {
	tEnv := getTestEnv()
	params := RequestRoutineParameters{
		OSPA: tEnv.ospa,
		ReqParams: RequestRoutineReqParameters{
			ClientUUID:      tEnv.ospa.ClientUUID,
			ServerIP:        net.ParseIP(tEnv.ospa.ServerHost),
			ServerPort:      tEnv.ospa.ServerPort,
			TargetProto:     lib.ProtocolTCP,
			ClientIP:        net.IPv4(88, 200, 23, 10),
			TargetIP:        net.IPv4(88, 200, 23, 19),
			TargetPortStart: 3000,
			TargetPortEnd:   8000,
		},
		AutoMode:   false,
		RetryCount: 1,
		Timeout:    time.Second,
	}

	resolvClient := crypto.NewPublicKeyResolverMock()
	cipherClient := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(tEnv.clientPrivateKey, resolvClient)
	resolvClient.On("PublicKey", mock.Anything).Return(tEnv.serverPublicKey, nil)

	resolvServer := crypto.NewPublicKeyResolverMock()
	resolvServer.On("PublicKey", mock.Anything).Return(tEnv.clientPublicKey, nil)
	cipherServer := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(tEnv.serverPrivateKey, resolvServer)

	preHookTriggered := false
	sender := &udpSenderStubServer{
		responderParams: stubServerResponderParams{
			Duration: time.Second,
		},
		cs: cipherServer,
		preHook: func(reqB []byte, dest net.UDPAddr, _ time.Duration) {
			destTarget := net.UDPAddr{
				IP:   params.ReqParams.ServerIP,
				Port: params.ReqParams.ServerPort,
			}
			assert.Equal(t, dest.String(), destTarget.String())

			req, err := lib.RequestUnmarshal(reqB, cipherServer)
			require.NoError(t, err)

			assert.NotEqual(t, uint8(0), req.Header.TransactionId)

			targetIP, err := lib.TargetIPFromContainer(req.Body)
			require.NoError(t, err)
			assert.True(t, params.ReqParams.TargetIP.Equal(targetIP))

			preHookTriggered = true
		},
	}

	opt := RequestRoutineOpt{Sender: sender}

	assert.NoError(t, RequestRoutine(params, cipherClient, opt))
	assert.True(t, preHookTriggered)
}

type testEnv struct {
	clientPrivateKey *rsa.PrivateKey
	clientPublicKey  *rsa.PublicKey
	serverPrivateKey *rsa.PrivateKey
	serverPublicKey  *rsa.PublicKey

	ospa OSPA
}

func getTestEnv() testEnv {
	t := testEnv{}

	var err error
	t.clientPrivateKey, t.clientPublicKey, err = crypto.RSAKeypair(2048)
	panicOnErr(err)
	t.serverPrivateKey, t.serverPublicKey, err = crypto.RSAKeypair(2048)
	panicOnErr(err)

	clientPrivKey, err := crypto.RSAEncodePrivateKey(t.clientPrivateKey)
	panicOnErr(err)
	clientPubKey, err := crypto.RSAEncodePublicKey(t.clientPublicKey)
	panicOnErr(err)

	serverPrivKey, err := crypto.RSAEncodePrivateKey(t.serverPrivateKey)
	panicOnErr(err)

	t.ospa = OSPA{
		Version:    OSPAFileVersion,
		ClientUUID: "372c1ae1-54a2-42ed-9b33-18449fd3cc9f",
		ServerHost: "88.200.23.19",
		ServerPort: lib.DefaultServerPort,
		Crypto: OSPACrypto{
			CipherSuitePriority: []string{
				crypto.MustCipherSuiteIdToString(crypto.CipherRSA_SHA256_AES256CBC_ID),
			},
			RSA: OSPACryptoRSA{
				Client: OSPACryptoRSAClient{
					PrivateKey: clientPrivKey,
					PublicKey:  clientPubKey,
				},
				Server: OSPACryptoRSAServer{
					PublicKey: serverPrivKey,
				},
			},
		},
	}

	return t
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

func TestPerformRequest(t *testing.T) {
	sender := &udpSenderMock{}
	cs := crypto.NewCipherSuiteStub()
	reqD := lib.RequestData{
		TransactionId:   42,
		ClientUUID:      "c3b66a05-9098-4100-8141-be5695ada0e7",
		ClientIP:        net.IPv4(88, 200, 23, 10),
		TargetProtocol:  lib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 22,
		TargetPortEnd:   22,
	}

	respD := lib.ResponseData{
		TransactionId:   42,
		TargetProtocol:  lib.ProtocolTCP,
		TargetIP:        reqD.TargetIP,
		TargetPortStart: reqD.TargetPortStart,
		TargetPortEnd:   reqD.TargetPortEnd,
		Duration:        time.Minute,
	}

	respT, err := lib.NewResponse(respD, cs)
	assert.NoError(t, err)
	respB, err := respT.Marshal()
	assert.NoError(t, err)

	server := net.UDPAddr{
		IP:   reqD.TargetIP,
		Port: lib.DefaultServerPort,
	}
	timeout := 100 * time.Millisecond

	sender.On("SendUDPRequest", mock.Anything, server, timeout).
		Return([]byte{}, errors.Wrap(errSocketRead, "fake timeout")).Twice()
	sender.On("SendUDPRequest", mock.Anything, server, timeout).Return(respB, nil).Once()

	resp, err := performRequest(sender, cs, reqD, server, performRequestParameters{
		retryCount: 3,
		timeout:    timeout,
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	sender.AssertExpectations(t)
	sender.AssertNumberOfCalls(t, "SendUDPRequest", 3)
}

func TestPerformRequest_Failure(t *testing.T) {
	sender := &udpSenderMock{}
	cs := crypto.NewCipherSuiteStub()
	reqD := lib.RequestData{
		TransactionId:   42,
		ClientUUID:      "c3b66a05-9098-4100-8141-be5695ada0e7",
		ClientIP:        net.IPv4(88, 200, 23, 10),
		TargetProtocol:  lib.ProtocolTCP,
		TargetIP:        net.IPv4(88, 200, 23, 19),
		TargetPortStart: 22,
		TargetPortEnd:   22,
	}

	server := net.UDPAddr{
		IP:   reqD.TargetIP,
		Port: lib.DefaultServerPort,
	}
	timeout := 100 * time.Millisecond

	sender.On("SendUDPRequest", mock.Anything, server, timeout).
		Return([]byte{}, errors.Wrap(errSocketRead, "fake timeout")).Times(3)

	resp, err := performRequest(sender, cs, reqD, server, performRequestParameters{
		retryCount: 3,
		timeout:    timeout,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)

	sender.AssertExpectations(t)
	sender.AssertNumberOfCalls(t, "SendUDPRequest", 3)
}
