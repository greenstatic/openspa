package openspalib

import (
	"fmt"
	"github.com/pkg/errors"
	"time"
)

const (
	ResponsePacketBodySize = 24 // bytes
)

type Response struct {
	Header Header
	Body   ResponseBody
}

type ResponseBody struct {
	Timestamp       time.Time
	Nonce           Nonce
	Protocol        InternetProtocolNumber
	StartPort       uint16
	EndPort         uint16
	Duration        time.Duration
	SignatureMethod SignatureMethod
	Signature       []byte
}

type ResponseData struct {
	Protocol        InternetProtocolNumber
	StartPort       uint16
	EndPort         uint16
	Duration        time.Duration
	SignatureMethod SignatureMethod
}

// Encode encodes the response packet body according to the OpenSPA specification.
func (body *ResponseBody) Encode() ([]byte, error) {
	// This is our packet body
	payloadBuff := make([]byte, ResponsePacketBodySize)

	offset := 0 // we initialize the offset to 0

	// Unix Timestamp - 64 bit = 8 bytes
	const timestampSize = 8 // bytes
	timestampBin := timestampEncode(body.Timestamp)

	for i := 0; i < timestampSize; i++ {
		payloadBuff[offset+i] = timestampBin[i]
	}

	offset += timestampSize

	// Nonce - 24 bits = 3 bytes
	for i := 0; i < nonceSize; i++ {
		payloadBuff[offset+i] = body.Nonce[i]
	}

	offset += nonceSize

	// Protocol - 8 bits = 1 byte
	const protocolSize = 1 // byte
	payloadBuff[offset] = body.Protocol.ToBin()

	offset += protocolSize

	// Start Port - 16 bits = 2 bytes
	const startPortSize = 2 // bytes
	startPort := encodePort(body.StartPort)

	for i := 0; i < startPortSize; i++ {
		payloadBuff[offset+i] = startPort[i]
	}

	offset += startPortSize

	// End Port - 16 bits = 2 bytes
	const endPortSize = 2 // bytes
	endPort := encodePort(body.EndPort)

	for i := 0; i < startPortSize; i++ {
		payloadBuff[offset+i] = endPort[i]
	}

	offset += endPortSize

	// Duration - 16 bits = 2 bytes
	const durationSize = 2 // bytes
	duration := encodeDuration(body.Duration)

	for i := 0; i < durationSize; i++ {
		payloadBuff[offset+i] = duration[i]
	}

	offset += durationSize

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	payloadBuff[offset] = body.SignatureMethod.ToBin()

	offset += signatureMethodSize

	// Reserved - 40 bits = 5 byte
	const reservedSize = 5 // bytes
	for i := 0; i < reservedSize; i++ {
		payloadBuff[offset+i] = 0
	}

	offset += reservedSize

	if offset != ResponsePacketBodySize {
		return nil, errors.New("encoded payload is not the correct size")
	}

	return payloadBuff, nil
}

// Decodes the packet payload according to the OpenSPA specification for request packet payload.
func responseDecode(data []byte) (body *ResponseBody, signature []byte, err error) {
	if len(data) < ResponsePacketBodySize {
		return nil, nil, errors.New(fmt.Sprintf(
			"raw response packet is too short to be an OpenSPA packet, length: %d bytes, expects at least: %d bytes (header+body unsigned)",
			len(data), ResponsePacketBodySize))
	}

	body = &ResponseBody{}

	// -- We start with the packet decoding

	offset := 0

	// UNIX Timestamp - 64 bits = 8 bytes
	const timestampSize = 8 // bytes
	timestamp, err := timestampDecode(data[offset : offset+timestampSize])
	if err != nil {
		return nil, nil, err
	}

	body.Timestamp = timestamp
	offset += timestampSize

	// Nonce - 24 bits = 3 bytes
	const nonceSize = 3 // bytes
	body.Nonce = data[offset : offset+nonceSize]
	offset += nonceSize

	// Protocol - 8 bits = 1 byte
	const protocolSize = 1 // byte
	body.Protocol = InternetProtocolNumber(data[offset])
	offset += protocolSize

	// Start Port - 16 bits = 2 bytes
	const startPortSize = 2 // bytes
	startPort, err := decodePort(data[offset:offset+startPortSize], body.Protocol)
	if err != nil {
		return nil, nil, err
	}

	body.StartPort = startPort
	offset += startPortSize

	// End Port - 16 bits = 2 bytes
	const endPortSize = 2 // bytes
	endPort, err := decodePort(data[offset:offset+endPortSize], body.Protocol)
	if err != nil {
		return nil, nil, err
	}

	body.EndPort = endPort
	offset += endPortSize

	// Duration - 16 bits = 2 byte
	const durationSize = 2 // bytes
	duration, err := decodeDuration(data[offset : offset+durationSize])
	if err != nil {
		return nil, nil, err
	}

	body.Duration = duration
	offset += durationSize

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	sigMethod, err := decodeSignatureMethod(data[offset])
	if err != nil {
		return nil, nil, err
	}

	body.SignatureMethod = sigMethod
	offset += signatureMethodSize

	// Reserved - 40 bits = 5 byte
	const reservedSize = 5 // byte
	offset += reservedSize

	// Signature - max 9648 bits = max 1206 bytes
	signature = data[offset:]

	// -- Finished with the decoding
	return
}
