/*
Package header implements the OpenSPA header specification.

Supports OpenSPA version 1 with the following encryption methods:
	* RSA 2048 with AES-256 CBC mode
*/

package header

import (
	"errors"
	"fmt"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/tools"
)

const (
	versionTotalMax uint8 = 15 // maximum possible version according to the OpenSPA protocol
	Size            int   = 2  // size of the header in bytes

	EncryptionMethod_RSA_2048_with_AES_256_CBC byte = 0x01

	encryptionMethodTotalMax uint8 = 63
)

var SupportedEncryptionMethods = []byte{EncryptionMethod_RSA_2048_with_AES_256_CBC}

type Header struct {
	Version          uint8
	IsRequest        bool
	EncryptionMethod byte
}

// Converts the inputted byte slice to a header if properly formatted.
// Otherwise we will return an error.
// The function will check the version strictly, meaning that if it
// does not match exactly we will return an error.
func Decode(data []byte) (Header, error) {

	header, err := binaryDecode(data)
	if err != nil {
		return Header{}, err
	}

	// This is a strict version check of the protocol. No backwards compatibility.
	if header.Version != openspalib.Version {
		return Header{}, errors.New(fmt.Sprintf("unsupported version (%v) of openspa", header.EncryptionMethod))
	}

	// Return error on unsupported encryption methods
	if !tools.ElementInSlice(header.EncryptionMethod, SupportedEncryptionMethods) {
		return Header{}, errors.New(fmt.Sprintf("encryption method: %v is not supported", header.EncryptionMethod))
	}

	return header, nil
}

// Encodes the header struct into a byte slice. If the header version specified
// is larger than the one specified in the source return an error. Checks that
// the encryption method is supported as well otherwise return an error.
func (header *Header) Encode() ([]byte, error) {

	// Reject header versions greater than the supported version
	if header.Version > openspalib.Version {
		return nil, errors.New("version number is unsupported")
	}

	if header.Version > versionTotalMax {
		return nil, errors.New("version number cannot be supported because the protocol does not have enough fields")
	}

	// Reject header encryption methods that are not supported
	if !tools.ElementInSlice(header.EncryptionMethod, SupportedEncryptionMethods) {
		return nil, errors.New("encryption method is not supported")
	}

	return header.binaryEncode(), nil
}
