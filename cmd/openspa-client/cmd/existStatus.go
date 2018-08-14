package cmd

const (
	_ = iota // exit status 0 is success, skip it
	unexpectedError
	badOSPAFile
	failedToReadServerPublicKey
	failedToReadClientPublicKey
	failedToReadClientPrivateKey

	failedToDecodeServerPublicKey
	failedToDecodeClientPublicKey
	failedToDecodeClientPrivateKey

	badPrameters
	failedToSendRequestPacket
	noResponseToRequestPacket

	failedToResolveIPs
)
