package main

import (
	"fmt"
	"net"
	"time"

	"github.com/greenstatic/openspa/openspalib"
)

func main() {
	// Client side
	//clientPrivKey, _ := openspalib.TestingRsaKeyPair1()
	//_, serverPubKey := openspalib.TestingRsaKeyPair2()
	//cipher := openspalib.RSA_AES_128_CBC_With_RSA_SHA256{
	//	ServerPubKey:  serverPubKey,
	//	ClientPrivKey: clientPrivKey,
	//}
	//_ = cipher

	//reqData := openspalib.RequestData{
	//	ClientDeviceID:  "6e75b3ed-a42b-4bc0-91fd-77801c4acebd",
	//	Protocol:        openspalib.ProtocolTCP,
	//	StartPort:       80,
	//	EndPort:         80,
	//	ClientBehindNat: true,
	//	ClientPublicIP:  net.IP{1,2,3,4},
	//	ServerPublicIP:  net.IP{8,8,8,8},
	//}
	//
	//reqBytes, err := openspalib.NewRequest(reqData, &openspalib.CryptoMethodMock{})
	//if err != nil {
	//	panic(err)
	//}

	// Client - send request
	cMux := openspalib_old.NewCipherSuiteMux()
	c := openspalib_old.CryptoMethodMock{}
	cMux.Apply(c)

	secCont := openspalib_old.NewEmptyTLVContainer()
	secCont.SetBytes(0xFA, []byte{0x12, 0x34})

	plainCont := openspalib_old.NewEmptyTLVContainer()
	plainCont.SetBytes(0xF9, []byte{0xAB, 0xCD})

	reqData := openspalib_old.RequestData{
		ClientDeviceUUID:        "6e75b3ed-a42b-4bc0-91fd-77801c4acebd",
		Protocol:                openspalib_old.ProtocolTCP,
		PortStart:               80,
		PortEnd:                 80,
		ClientPublicIPv4:        net.IP{1, 2, 3, 4},
		ServerPublicIPv4:        net.IP{1, 1, 1, 1},
		ClientBehindNat:         true,
		AdditionalSecureData:    secCont,
		AdditionalPlaintextData: plainCont,
	}

	reqClient := openspalib_old.NewRequest(reqData)
	reqBytes, err := reqClient.SignAndEncrypt(c)
	if err != nil {
		panic(err)
	}

	// Server - request process and send response
	reqServer, err := openspalib_old.RequestParse(reqBytes, cMux)
	if err != nil {
		panic(err)
	}

	respData := openspalib_old.ResponseData{
		Protocol:                reqServer.SecureContainer.Protocol,
		PortStart:               reqServer.SecureContainer.PortStart,
		PortEnd:                 reqServer.SecureContainer.PortEnd,
		Duration:                time.Nanosecond,
		AdditionalSecureData:    nil,
		AdditionalPlaintextData: nil,
	}

	respServer := openspalib_old.NewResponse(respData, reqServer.Header.TransactionId)
	respBytes, err := respServer.SignAndEncrypt(c)
	if err != nil {
		panic(err)
	}

	// Client - response process
	respClient, err := openspalib_old.ResponseParse(respBytes, cMux)
	if err != nil {
		panic(err)
	}

	_ = respClient

	fmt.Println("DONE")
}
