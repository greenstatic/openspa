package response

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/header"
	"github.com/greenstatic/openspalib/tools"
	"time"
)

// Returns the data slice without the header (note, here we simply cut off
// the header size from the slice, no smart lookup if it's actually the header.
func removeHeader(data []byte) ([]byte, error) {
	if len(data) < header.Size {
		return nil, errors.New("inputted data is too small to contain a header")
	}

	return data[header.Size:], nil
}

// Decodes the packet payload according to the OpenSPA specification
// for request packet payload.
func decode(data []byte) (p packetPayload, signature []byte, err error) {

	if len(data) < PacketPayloadSize {
		return packetPayload{}, nil, errors.New(fmt.Sprintf(
			"raw response packet is too short to be an OpenSPA packet, length: %d bytes, expects at least: %d bytes (header+body unsigned)",
			len(data), PacketPayloadSize))
	}

	p = packetPayload{}

	// -- We start with the packet decoding

	offset := 0

	// UNIX Timestamp - 64 bits = 8 bytes
	const timestampSize = 8 // bytes
	timestamp, err := decodeTimestamp(data[offset : offset+timestampSize])
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.Timestamp = timestamp
	offset += timestampSize

	// Nonce - 24 bits = 3 bytes
	const nonceSize = 3 // bytes
	p.Nonce = data[offset : offset+nonceSize]
	offset += nonceSize

	// Protocol - 8 bits = 1 byte
	const protocolSize = 1 // byte
	p.Protocol = data[offset]
	offset += protocolSize

	// Start Port - 16 bits = 2 bytes
	const startPortSize = 2 // bytes
	startPort, err := decodePort(data[offset : offset+startPortSize], p.Protocol)
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.StartPort = startPort
	offset += startPortSize

	// End Port - 16 bits = 2 bytes
	const endPortSize = 2 // bytes
	endPort, err := decodePort(data[offset : offset+endPortSize], p.Protocol)
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.EndPort = endPort
	offset += endPortSize

	// Duration - 16 bits = 2 byte
	const durationSize = 2 // bytes
	duration, err := decodeDuration(data[offset : offset+durationSize])
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.Duration = duration
	offset += durationSize

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	sigMethod, err := decodeSignatureMethod(data[offset])
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.SignatureMethod = sigMethod
	offset += signatureMethodSize

	// Reserved - 40 bits = 5 byte
	const reservedSize = 5 // byte
	offset += reservedSize

	// Signature - max 9648 bits = max 1206 bytes
	signature = data[offset:]

	// -- Finished with the decoding
	return
}

// Decodes an 8-byte timestamp byte slice into a time.Time field
func decodeTimestamp(data []byte) (time.Time, error) {

	const timestampSize = 8 // bytes

	if len(data) != timestampSize {
		return time.Time{}, errors.New("inputted slice is not 8 bytes long")
	}

	var timestampInt int64

	// decode the byte slice into an int64
	timestampBuff := bytes.NewReader(data)
	err := binary.Read(timestampBuff, binary.BigEndian, &timestampInt)

	if err != nil {
		// Failed to decode timestamp
		return time.Time{}, err
	}

	return time.Unix(timestampInt, 0), nil
}

// Decodes a 2-byte slice that represents a port. Port 0 is disallowed and
// will trigger an error.
func decodePort(data []byte, protocol byte) (uint16, error) {
	port := binary.BigEndian.Uint16(data)

	portCanBeZero := tools.PortCanBeZero(protocol)
	if !portCanBeZero && port == 0 {
		return 0, errors.New("port 0 is disallowed")
	}

	return port, nil
}

// Decodes a 2-byte duration slice.
func decodeDuration(data []byte) (uint16, error) {
	duration := binary.BigEndian.Uint16(data)
	return duration, nil
}

// Decodes a byte signature method. Checks if the signature method
// is supported.
func decodeSignatureMethod(data byte) (byte, error) {
	if !tools.ElementInSlice(data, openspalib.SupportedSignatureMethods()) {
		return 0, errors.New("unsupported signature method:" + fmt.Sprintf("%x", data))
	}

	return data, nil
}
