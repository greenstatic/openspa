package openspalib_old

import (
	"fmt"
)

const (
	Version     = 2                       // version of the protocol
	PDUMaxSize  = 1408                    // bytes (UDP payload i.e. OpenSPA header + body)
	BodyMaxSize = PDUMaxSize - HeaderSize // bytes
)

type ErrCipherSuiteNotSupported struct {
	cipherSuite CipherSuiteId
}

func (e ErrCipherSuiteNotSupported) Error() string {
	return fmt.Sprintf("cipher suite %d not supported", uint8(e.cipherSuite))
}
