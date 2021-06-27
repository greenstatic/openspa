package openspalib

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
)

// PDU Header binary format:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|T|   Reserved    |   Cipher Suite    |  Body Offset  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// * Version (4 bits): Specifies the version of the protocol (0001 = v1).
// * Type (1 bit): Denotes the packet payload type (0=request, 1=response).
// * Reserved (9 bits): Field reserved for future use.
// * Cipher Suite (10 bits): The method the payload is encrypted and signed
// * PDU Body Offset (8 bits): Offset, where the PDU Body starts
//
// 4 + 1 + 9 + 10 + 8 = 32 bits = 4 bytes total header size

const (
	Version    = 2 // version of the protocol
	HeaderSize = 4 // size of the header in bytes
)

var (
	ErrHeaderInvalid = errors.New("header invalid")
)

// Header represents the head of an OpenSPA packet (request or response).
type Header struct {
	Version       uint8  // Protocol version
	IsRequest     bool   // Is an OpenSPA request, if false then it is an OpenSPA response
	CipherSuite   CipherSuiteId

	// Offset where the PDU Body begins
	PduBodyOffset uint8
}

type ErrProtocolVersionNotSupported struct {
	version uint8
}

func (e ErrProtocolVersionNotSupported) Error() string {
	return fmt.Sprintf("protocol version %d not supported", e.version)
}

// Encode encodes the header struct into a byte slice. If the header version specified is larger than the one
// specified in the source, return an error. Checks that the encryption method is supported as well, otherwise return
// an error.
func (header *Header) Encode() ([]byte, error) {
	// Reject header versions that do not match the supported protocol versions
	if header.Version != Version {
		return nil, ErrProtocolVersionNotSupported{header.Version}
	}

	// Reject encryption methods that are not supported
	if !CipherSuiteIsSupported(header.CipherSuite) {
		return nil, ErrCipherSuiteNotSupported{header.CipherSuite}
	}

	return headerMarshal(*header)
}

// HeaderDecode converts the inputted byte slice to a header if properly formatted. The function will check the version
// strictly, meaning that if it does not match exactly the version of this library we will return an error.
func HeaderDecode(data []byte) (Header, error) {
	header, err := headerUnmarshal(data)
	if err != nil {
		return Header{}, err
	}

	// This is a strict version check of the protocol. No backwards compatibility.
	if header.Version != Version {
		//return Header{}, fmt.Errorf("unsupported version (%v) of openspa", header.Version)
		return Header{}, ErrProtocolVersionNotSupported{header.Version}
	}

	// Return error on unsupported encryption methods
	if !CipherSuiteIsSupported(header.CipherSuite) {
		//return Header{}, fmt.Errorf("encryption method: %v is not supported", header.EncryptionMethod)
		return Header{}, ErrCipherSuiteNotSupported{header.CipherSuite}
	}

	return header, nil
}

// Converts a Header into it's byte representation according to the OpenSPA specification. This function does not
// perform any validation it merely does a dumb mapping of the header values to it's binary form. It will overflow if
// given values that are too large. It is up to the caller to check if the values make sense.
// ---------------------------------------------------------------------------------------------------------------------
// This function returns a byte slice and does not accept a io.Writer interface because according to our benchmarks,
// it is slower:
//
// $ go test -test.bench . -test.run ^$
// goos: darwin
// goarch: amd64
// pkg: github.com/greenstatic/openspa/openspalib
// cpu: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz
// BenchmarkHeaderMarshal
// BenchmarkHeaderMarshal-8      	87877300	        14.41 ns/op
// Benchmark__HeaderMarshal2
// Benchmark__HeaderMarshal2-8   	46393939	        28.10 ns/op
// PASS
func headerMarshal(h Header) ([]byte, error) {
	buffer := make([]byte, HeaderSize)

	// Version
	// 0000 VVVV << 4
	// VVVV TRRR
	buffer[0x0] = h.Version << 4

	// Packet Type
	if !h.IsRequest {
		// Request packet
		//   0000 1000  <- 0x08
		// | VVVV TRRR ... T=1
		//	-----------
		//   VVVV T000
		buffer[0x0] = buffer[0x0] | 0x08
	}

	cs := h.CipherSuite.ToBin()

	// Cipher Suite
	//   0011 1111 1111
	// & RRCC CCCC CCCC
	buffer[0x1] = cs[0] & 0x3
	buffer[0x2] = cs[1]

	// PDU Body Offset
	buffer[0x3] = h.PduBodyOffset

	return buffer, nil
}

// This function should not be used, please use headerMarshal. __headerMarshal2 is merely used to benchmark the
// difference between the writer interface vs. a byte slice.
func __headerMarshal2(h Header, w io.Writer) error {
	buffer := make([]byte, HeaderSize)

	// Version
	// 0000 VVVV << 4
	// VVVV TRRR
	buffer[0x0] = h.Version << 4

	// Packet Type
	if !h.IsRequest {
		// Request packet
		//   0000 1000  <- 0x08
		// | VVVV TRRR ... T=1
		//	-----------
		//   VVVV T000
		buffer[0x0] = buffer[0x0] | 0x08
	}

	cs := h.CipherSuite.ToBin()
	// Cipher Suite
	//   0011 1111 1111
	// & RRCC CCCC CCCC
	buffer[0x1] = cs[0] & 0x3
	buffer[0x2] = cs[1]

	buffer[0x3] = h.PduBodyOffset

	w.Write(buffer)

	return nil
}

// Converts a byte slice into a header struct according to the OpenSPA specification. Does not validate any binary
// according to the specification it merely does a dumb mapping of binary to the OpenSPA specification.
func headerUnmarshal(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, ErrHeaderInvalid
	}

	headerBin := data[:HeaderSize]
	/// Version (V) 4 bits || Packet Type (T) 1 bit || Reserved (R) 5 bits || Cipher Suite (C) 6 bits

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

	// Cipher Suite
	//   0011 1111 1111
	// & RRCC CCCC CCCC
	csH := headerBin[0x1] & 0x3
	csL := headerBin[0x2]

	cs := uint16(csL)
	cs = cs | (uint16(csH) << 8)

	cipherS := CipherSuiteId(cs)

	pduBodyOffset := headerBin[0x3]

	return Header{
		Version:       ver,
		IsRequest:     isRequest,
		CipherSuite:   cipherS,
		PduBodyOffset: pduBodyOffset,
	}, nil
}

// TODO - do we have to remove this?
// Returns the byte slice without the header (note, here we simply cut off the header size from the slice, no smart
// lookup if it's actually the header. We do not make a copy of the input byte slice, so be careful with the returned
// slice.
//func removeHeader(data []byte) ([]byte, error) {
//	if len(data) < HeaderSize {
//		return nil, errors.New("inputted data is too small to contain a header")
//	}
//
//	return data[HeaderSize:], nil
//}
