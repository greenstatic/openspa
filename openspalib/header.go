package openspalib

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"math"
)

// All numbers are encoded in big endian format
// PDU Header binary format:
// 0               |   1           |       2       |           3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Control Field |     TID   |    Cipher Suite   | Offset Mult.|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Reserved for eBPF optimization               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Additional Header Data (optional)               |
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
// * TID: Transaction ID (6 bits):
//		This should be a random uint (big endian) number representing a request/response exchange.
// * Cipher Suite (10 bits):
//		The method the payload is encrypted and signed
// * PDU Body Offset Multiplicand (1 byte)
//		PDU Body Offset = PDU Body Offset Multiplicand * 4
//		The offset from the fixed header that the PDU Body starts or in other words the number of bytes the additional
//	 	header data field takes. This value can be 0 (i.e. additional header data is empty).
// * Additional Header Data (optional, variable number of bits):
//		This field can encode additional data that will NOT be encrypted, since it is in the header. If you wish to
//		add additional data that will be encrypted, see the PDU body Additional Body Data field.
//		Data is encoded as TLV where the Type and Length values are both 2 bytes. Example:
//		The type 0x3F with a value of 0x1234 would be encoded as: 0x00 0x3F 0x00 0x02 0x12 0x34

const (
	Version                    uint8 = 2 // version of the protocol
	HeaderFixedSize                  = 8 // size of the fixed header in bytes (i.e. without additional header data)
	pduBodyOffsetMultiplier          = 4
	pduBodyOffsetMax                 = 0xFF * pduBodyOffsetMultiplier
	additionalHeaderDataLenMax       = pduBodyOffsetMax
)

var (
	ErrHeaderTooShort              = errors.New("header too short")
	ErrHeaderInvalid              = errors.New("header invalid")
	ErrAdditionalHeaderDataTooLong = errors.New("additional header data too long")
)

type ErrProtocolVersionNotSupported struct {
	version uint8
}

func (e ErrProtocolVersionNotSupported) Error() string {
	return fmt.Sprintf("protocol version %d not supported", e.version)
}

// Header represents the head of an OpenSPA packet (request or response).
type Header struct {
	controlField  byte
	TransactionId uint8
	CipherSuite   CipherSuiteId

	// Format is: 2 bytes for tag ID, 2 bytes for length and then the number of bytes defined by the length
	AdditionalHeaderData TLVContainer
}

func (header *Header) Type() PDUType {
	t, _ := controlFieldDecode(header.controlField)
	return t
}

func (header *Header) SetType(pduType PDUType) {
	_, v := controlFieldDecode(header.controlField)
	header.controlField = controlFieldEncode(pduType, v)
}

func (header *Header) Version() uint8 {
	_, ver := controlFieldDecode(header.controlField)
	return ver
}

func (header *Header) SetVersion(version uint8) {
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

	if header.AdditionalHeaderData != nil && header.AdditionalHeaderData.BytesBufferLen() > additionalHeaderDataLenMax {
		return nil, ErrAdditionalHeaderDataTooLong
	}

	return headerMarshal(*header)
}

func (header *Header) pduBodyOffsetMultiplicand() uint8 {
	t := header.AdditionalHeaderData
	if t == nil {
		return 0
	}

	l := t.BytesBufferLen()

	f := float64(l) / float64(pduBodyOffsetMultiplier)

	return uint8(math.Ceil(f))
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

	ahd1 := header.AdditionalHeaderData
	ahd2 := h.AdditionalHeaderData

	if ahd1 != nil && ahd2 == nil || ahd1 == nil && ahd2 != nil {
		return false
	}

	if ahd1 != nil && ahd2 != nil {
		b1, err := io.ReadAll(ahd1.BytesBuffer())
		if err != nil {
			panic(err)
		}

		b2, err := io.ReadAll(ahd2.BytesBuffer())
		if err != nil {
			panic(err)
		}

		if !bytes.Equal(b1, b2) {
			return false
		}

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
// BenchmarkHeaderMarshal-8      	87877300	        14.41 ns/op
// Benchmark__HeaderMarshal2
// Benchmark__HeaderMarshal2-8   	46393939	        28.10 ns/op
// PASS
func headerMarshal(h Header) ([]byte, error) {
	buffer := make([]byte, HeaderFixedSize)

	buffer[0x00] = h.controlField

	// Transaction ID and Cipher Suite
	tId := h.TransactionId << 2
	cs := h.CipherSuite.ToBin()

	// The two least significant bits of the tID byte contain the most significant bits of the Cipher Suite
	tId |= cs[0] & 0b0000_0011
	buffer[0x01] = tId
	buffer[0x02] = cs[1]

	// PDU Body Offset
	pduBodyOffsetMultiplicand := h.pduBodyOffsetMultiplicand()
	buffer[0x03] = pduBodyOffsetMultiplicand

	// Field Reserved for eBPF optimization
	buffer[0x04] = 0
	buffer[0x05] = 0
	buffer[0x06] = 0
	buffer[0x07] = 0

	// Additional Header Data (optional)
	if h.AdditionalHeaderData != nil {
		b, err := io.ReadAll(h.AdditionalHeaderData.BytesBuffer())
		if err != nil {
			return nil, errors.Wrap(err, "io read all additional header data")
		}

		buffer = append(buffer, b...)
		slack := additionalHeaderDataSlack(pduBodyOffsetMultiplicand, len(b))
		if slack != nil && len(slack) > 0 {
			buffer = append(buffer, slack...)
		}
	}

	return buffer, nil
}

// This function should not be used, please use headerMarshal. __headerMarshal2 is merely used to benchmark the
// difference between the writer interface vs. a byte slice.
func __headerMarshal2(h Header, w io.Writer) error {
	buffer := make([]byte, HeaderFixedSize)
	buffer[0x00] = controlFieldEncode(h.Type(), h.Version())

	// Transaction ID and Cipher Suite
	tId := h.TransactionId << 2
	cs := h.CipherSuite.ToBin()

	// The two least significant bits of the tID byte contain the most significant bits of the Cipher Suite
	tId |= cs[0] & 0b0000_0011
	buffer[0x01] = tId
	buffer[0x02] = cs[1]

	// PDU Body Offset
	pduBodyOffsetMultiplicand := h.pduBodyOffsetMultiplicand()
	buffer[0x03] = pduBodyOffsetMultiplicand


	// Additional Header Data (optional)
	if h.AdditionalHeaderData != nil {
		b, err := io.ReadAll(h.AdditionalHeaderData.BytesBuffer())
		if err != nil {
			return errors.Wrap(err, "io read all additional header data")
		}

		buffer = append(buffer, b...)
		slack := additionalHeaderDataSlack(pduBodyOffsetMultiplicand, len(b))
		if slack != nil && len(slack) > 0 {
			buffer = append(buffer, slack...)
		}
	}

	_, err := w.Write(buffer)
	if err != nil {
		return errors.Wrap(err, "write to buffer")
	}

	return nil
}

// Converts a byte slice into a header struct according to the OpenSPA specification. Does not validate any binary
// according to the specification it merely does a dumb mapping of binary to the OpenSPA specification.
func headerUnmarshal(data []byte) (Header, error) {
	if len(data) < HeaderFixedSize {
		return Header{}, ErrHeaderTooShort
	}

	h := Header{}

	h.controlField = data[0x0]

	// Transaction ID
	h.TransactionId = data[0x1] >> 2

	// Cipher Suite
	//   0011 1111 1111
	// & TTCC CCCC CCCC
	csH := data[0x1] & 0b0011
	csL := data[0x2]
	h.CipherSuite = CipherSuiteId(binary.BigEndian.Uint16([]byte{csH, csL}))

	pduBodyOffsetMultiplicand := data[0x3]
	pduBodyOffset := pduBodyOffset(pduBodyOffsetMultiplicand)
	if HeaderFixedSize + pduBodyOffset > len(data) {
		return Header{}, ErrHeaderInvalid
	}

	if pduBodyOffset != 0 {
		if HeaderFixedSize + pduBodyOffset > len(data) {
			return Header{}, ErrHeaderTooShort
		}

		h.AdditionalHeaderData = NewTLVContainer(data[HeaderFixedSize : HeaderFixedSize+pduBodyOffset], additionalHeaderDataLenMax)
	}

	return h, nil
}

func controlFieldEncode(t PDUType, version uint8) byte {
	b := version << 4

	if t == PDUResponseType {
		b |= 0b1000_0000
	} else {
		// response, make sure bit 7 is 0
		b &= 0b0111_1111
	}

	return b
}

func controlFieldDecode(b byte) (t PDUType, version uint8) {
	version = (b >> 4) & 0b0000_0111

	if (b >> 7) & 0b0000_0001 == 0x00 {
		t = PDURequestType
	} else {
		t = PDUResponseType
	}
	return
}

func additionalHeaderDataSlack(pduBodyOffsetMultiplicand uint8, tlvContainerLen int) []byte {
	slackBytes := pduBodyOffset(pduBodyOffsetMultiplicand) - tlvContainerLen
	if slackBytes < 0 {
		panic("invalid pdu body offset multiplicand")
	}
	return make([]byte, slackBytes)
}

func pduBodyOffset(multiplicand uint8) int {
	return int(multiplicand) * pduBodyOffsetMultiplier
}