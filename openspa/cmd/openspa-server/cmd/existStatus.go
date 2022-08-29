package cmd

const (
	_ = iota // exit status 0 is success, skip it
	unexpectedError
	failedToReadConfig
	failedToReadServerPublicKey
	failedToReadServerPrivateKey

	failedToDecodeServerPublicKey
	failedToDecodeServerPrivateKey
)
