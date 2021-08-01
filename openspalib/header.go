package openspalib

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
)

// PDU Header binary format:
// 0               |   1           |       2       |           3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Control Field | Transaction ID|  Cipher Suite |   Reserved  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Reserved for ADK                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           PDU Body                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// ----------------------------------------------------------------------
// Control field (1 byte)
// 	7 6 5 4 3 2 1 0
// 	+-+-+-+-+-+-+-+-+
// 	|T|V|V|V|R|R|R|R|
// 	+-+-+-+-+-+-+-+-+
//
// Control field bit 7: PDU Type (1 bit)
// 	| Bit 7 | PDU Type  |
// 	|-------|-----------|
// 	| 0     | Request   |
// 	| 1     | Response  |
//
// Control field bit 4-6: OpenSPA Version (3 bits)
// 	| Bit 6 | Bit 5 | Bit 4 | Version   |
// 	|-------|-------|-------|-----------|
// 	| 0     | 0     | 0     | Invalid   |
// 	| 0     | 0     | 1     | Version 1 |
// 	| 0     | 1     | 0     | Version 2 |
// 	| 0     | 1     | 1     | Version 3 |
// 	| 1     | 0     | 0     | Version 4 |
// 	| 1     | 0     | 1     | Version 5 |
// 	| 1     | 1     | 0     | Version 6 |
// 	| 1     | 1     | 1     | Version 7 |
//
// Control field bit 0-3: Reserved
// Should be set to all 0's.
// ----------------------------------------------------------------------
// * Control Field (1 byte):
//		Various data regarding the PDU body, e.g. request or response, protocol version.
// * TID: Transaction ID (1 byte):
//		This should be a random uint (big endian) number representing a request/response exchange.
// * Cipher Suite (1 byte):
//		The method the payload is encrypted and signed
// * ADK: Anti DoS-Knocking Protection (4 bytes):
//		Field is reserved.
// * PDU Body (variable number of bytes):
//		Data encoded using TLV (Type-Length-Value) where the type is defined using 2 bytes (big endian), length in 1
//		byte (uint8) and value a variable number of bytes - as defined by the length field.
//		The type 0x3F with a value of 0x1234 would be encoded as: 0x00 0x3F 0x02 0x12 0x34.
//
// Integers are encoded in big endian format.

const HeaderSize = 8 // bytes

var ErrHeaderTooShort = errors.New("header too short")

type ErrProtocolVersionNotSupported struct {
	version int
}

func (e ErrProtocolVersionNotSupported) Error() string {
	return fmt.Sprintf("protocol version %d not supported", e.version)
}

// Header represents the head of an OpenSPA packet (request or response).
type Header struct {
	controlField  uint8
	TransactionId uint8
	CipherSuite   CipherSuiteId
}

func (header *Header) Type() PDUType {
	t, _ := controlFieldDecode(header.controlField)
	return t
}

func (header *Header) SetType(pduType PDUType) {
	_, v := controlFieldDecode(header.controlField)
	header.controlField = controlFieldEncode(pduType, v)
}

func (header *Header) Version() int {
	_, ver := controlFieldDecode(header.controlField)
	return ver
}

func (header *Header) SetVersion(version int) {
	t, _ := controlFieldDecode(header.controlField)
	header.controlField = controlFieldEncode(t, version)
}

// Encode encodes the header struct into a byte slice. If the header version specified is larger than the one
// specified in the source, return an error. Checks that the encryption method is supported as well, otherwise return
// an error.
func (header *Header) Encode() ([]byte, error) {
	// Reject header versions that do not match the supported protocol versions
	if header.Version() != Version {
		return nil, ErrProtocolVersionNotSupported{header.Version()}
	}

	// Reject encryption methods that are not supported
	if !CipherSuiteIsSupported(header.CipherSuite) {
		return nil, ErrCipherSuiteNotSupported{header.CipherSuite}
	}

	return headerMarshal(*header)
}

// Equal returns true if the supplied header is semantically equal to the structs header, otherwise false.
func (header *Header) Equal(h Header) bool {
	if header.Version() != h.Version() {
		return false
	}

	if header.Type() != h.Type() {
		return false
	}

	if header.TransactionId != h.TransactionId {
		return false
	}

	if header.CipherSuite != h.CipherSuite {
		return false
	}

	return true
}

// HeaderDecode converts the inputted byte slice to a header if properly formatted. The function will check the version
// strictly, meaning that if it does not match exactly the version of this library we will return an error.
func HeaderDecode(data []byte) (Header, error) {
	header, err := headerUnmarshal(data)
	if err != nil {
		return Header{}, err
	}

	// This is a strict version check of the protocol. No backwards compatibility.
	if v := header.Version(); v != Version {
		return Header{}, ErrProtocolVersionNotSupported{v}
	}

	// Return error on unsupported encryption methods
	if !CipherSuiteIsSupported(header.CipherSuite) {
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
// BenchmarkHeaderMarshal-8      	57187353	        18.15 ns/op
// Benchmark__HeaderMarshal2
// Benchmark__HeaderMarshal2-8   	45415515	        26.98 ns/op
// PASS
func headerMarshal(h Header) ([]byte, error) {
	buffer := make([]byte, HeaderSize)

	buffer[0x0] = h.controlField
	buffer[0x1] = h.TransactionId
	buffer[0x2] = h.CipherSuite.Bin()

	// Field Reserved for ADK
	buffer[0x4] = 0
	buffer[0x5] = 0
	buffer[0x6] = 0
	buffer[0x7] = 0

	return buffer, nil
}

// This function should not be used, please use headerMarshal. __headerMarshal2 is merely used to benchmark the
// difference between the writer interface vs. a byte slice.
func __headerMarshal2(h Header, w io.Writer) error {
	_, err := w.Write([]byte{
		h.controlField,
		h.TransactionId,
		h.CipherSuite.Bin(),
	})
	if err != nil {
		return errors.Wrap(err, "write to buffer")
	}

	return nil
}

// Converts a byte slice into a header struct according to the OpenSPA specification. Does not validate any binary
// according to the specification it merely does a dumb mapping of binary to the OpenSPA specification.
func headerUnmarshal(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, ErrHeaderTooShort
	}

	h := Header{
		controlField:  data[0x0],
		TransactionId: data[0x1],
		CipherSuite:   CipherSuiteId(data[0x2]),
	}

	return h, nil
}

func controlFieldEncode(t PDUType, version int) byte {
	b := uint8(version) << 4

	if t == PDUResponseType {
		b |= 0b1000_0000
	} else {
		// response, make sure bit 7 is 0
		b &= 0b0111_1111
	}

	return b
}

func controlFieldDecode(b uint8) (t PDUType, version int) {
	version = int((b >> 4) & 0b0000_0111)

	if (b >> 7) & 0b0000_0001 == 0x00 {
		t = PDURequestType
	} else {
		t = PDUResponseType
	}
	return
}
