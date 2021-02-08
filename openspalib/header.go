package openspalib

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
)

const (
	HeaderSize int = 2 // size of the header in bytes

	CryptoSuite_RSA_2048_WITH_AES_256_CBC uint8 = 0x01
	cryptoSuiteFieldMax                   uint8 = 63
)

var (
	SupportedCryptoSuites = []uint8{CryptoSuite_RSA_2048_WITH_AES_256_CBC}
)

type Header struct {
	Version     uint8
	IsRequest   bool
	CryptoSuite uint8
}

// Encodes the header struct into a byte slice. If the header version specified
// is larger than the one specified in the source return an error. Checks that
// the encryption method is supported as well otherwise return an error.
func (header *Header) Encode(out io.Writer) error {
	// Reject header versions that do not match the supported protocol versions
	if header.Version != Version {
		return errors.New("protocol version number is unsupported")
	}

	// Reject crypto suites that are not supported
	if !byteInSlice(header.CryptoSuite, SupportedCryptoSuites) {
		return errors.New("crypto suite is not supported")
	}

	return header.marshal(out)
}

// Converts the inputted byte slice to a header if properly formatted.
// Otherwise we will return an error.
// The function will check the version strictly, meaning that if it
// does not match exactly we will return an error.
func Decode(data []byte) (Header, error) {

	header, err := headerUnmarshal(data)
	if err != nil {
		return Header{}, err
	}

	// This is a strict version check of the protocol. No backwards compatibility.
	if header.Version != Version {
		return Header{}, errors.New(fmt.Sprintf("unsupported version (%v) of openspa", header.CryptoSuite))
	}

	// Return error on unsupported encryption methods
	if !byteInSlice(header.CryptoSuite, SupportedCryptoSuites) {
		return Header{}, errors.New(fmt.Sprintf("encryption method: %v is not supported", header.CryptoSuite))
	}

	return header, nil
}

// Converts a a header struct into a byte slice according to the OpenSPA specification.
// Does not validate any binary according to the specification it merely does a dumb
// mapping of binary to the OpenSPA specification. It will overflow if given values that
// are too large. It is up to the caller to check if the values make sense.
func (header *Header) marshal(out io.Writer) error {
	buffer := make([]byte, HeaderSize)

	// Version
	// 0000 VVVV << 4
	// VVVV TRRR
	buffer[0x0] = header.Version << 4

	// Packet Type
	if !header.IsRequest {
		// Request packet
		//   0000 1000  <- 0x08
		// | VVVV TRRR ... T=1
		//	-----------
		//   VVVV T000
		buffer[0x0] = buffer[0x0] | 0x08
	}

	// Crypto Suite
	// 	 0011 1111	<- 0x3f
	// & RRCC CCCC
	// ------------
	//   00CC CCCC
	buffer[0x1] = 0x3F & header.CryptoSuite

	_, err := out.Write(buffer)
	return err
}

// Converts a byte slice into a header struct according to the OpenSPA specification.
// Does not validate any binary according to the specification it merely does a dumb
// mapping of binary to the OpenSPA specification.
func headerUnmarshal(data []byte) (header Header, err error) {

	if len(data) < HeaderSize {
		return Header{}, errors.New("data too short to be an openspa header")
	}

	headerBin := data[:HeaderSize]
	/// Version (V) 4 bits || Packet Type (T) 1 bit || Reserved (R) 5 bits || Crypto Suite (C) 6 bits

	// Version
	// VVVV TRRR >> 4 =
	// 0000 VVVV
	ver := uint8(headerBin[0x0] >> 4)

	// Packet Type
	//   0000 1111  <- 0x0F
	// & VVVV TRRR
	//	-----------
	//   0000 TRRR >> 3 =
	//   0000 000T
	typeOfPacket := (headerBin[0x0] & 0x0F) >> 3

	isRequest := typeOfPacket == 0

	// Crypto Suite
	// 	 0011 1111	<- 0x3f
	// & RRCC CCCC
	// ------------
	//   00CC CCCC
	cryptoSuite := 0x3F & headerBin[0x1]

	return Header{ver, isRequest, cryptoSuite}, nil
}
