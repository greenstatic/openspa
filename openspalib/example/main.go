package main

import (
	"net"

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

	reqData := openspalib.RequestData{
		ClientDeviceID:  "6e75b3ed-a42b-4bc0-91fd-77801c4acebd",
		Protocol:        openspalib.ProtocolTCP,
		StartPort:       80,
		EndPort:         80,
		ClientBehindNat: true,
		ClientPublicIP:  net.IP{1,2,3,4},
		ServerPublicIP:  net.IP{8,8,8,8},
	}

	reqBytes, err := openspalib.NewRequest(reqData, &openspalib.CryptoMethodMock{})
	if err != nil {
		panic(err)
	}

	// Send over the wire reqBytes

	// Server side
	_ = reqBytes


}
