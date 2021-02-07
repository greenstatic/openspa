package response

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Encodes the packet payload according to the OpenSPA specification
// for response packet payload.
func (p *packetPayload) Encode() ([]byte, error) {

	// This is our packet payload
	payloadBuff := make([]byte, PacketPayloadSize)

	offset := 0 // we initialize the offset to 0

	// Unix Timestamp - 64 bit = 8 bytes
	const timestampSize = 8 // bytes
	timestampBin := encodeTimestamp(p.Timestamp)

	for i := 0; i < timestampSize; i++ {
		payloadBuff[offset+i] = timestampBin[i]
	}

	offset += timestampSize

	// Nonce - 24 bits = 3 bytes
	for i := 0; i < nonceSize; i++ {
		payloadBuff[offset+i] = p.Nonce[i]
	}

	offset += nonceSize

	// Protocol - 8 bits = 1 byte
	const protocolSize = 1 // byte
	payloadBuff[offset] = p.Protocol

	offset += protocolSize

	// Start Port - 16 bits = 2 bytes
	const startPortSize = 2 // bytes
	startPort := encodePort(p.StartPort)

	for i := 0; i < startPortSize; i++ {
		payloadBuff[offset+i] = startPort[i]
	}

	offset += startPortSize

	// End Port - 16 bits = 2 bytes
	const endPortSize = 2 // bytes
	endPort := encodePort(p.EndPort)

	for i := 0; i < startPortSize; i++ {
		payloadBuff[offset+i] = endPort[i]
	}

	offset += endPortSize

	// Duration - 16 bits = 2 bytes
	const durationSize = 2 // bytes
	duration := encodeDuration(p.Duration)

	for i := 0; i < durationSize; i++ {
		payloadBuff[offset+i] = duration[i]
	}

	offset += durationSize

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	payloadBuff[offset] = p.SignatureMethod

	offset += signatureMethodSize

	// Reserved - 40 bits = 5 byte
	const reservedSize = 5 // bytes
	for i := 0; i < reservedSize; i++ {
		payloadBuff[offset+i] = 0
	}

	offset += reservedSize

	if offset != PacketPayloadSize {
		return nil, errors.New("encoded payload is not the correct size")
	}

	return payloadBuff, nil
}

// Encodes a time.Time field into a unix 64-bit timestamp - 8 byte slice
func encodeTimestamp(timestamp time.Time) []byte {

	timestampBinBuffer := new(bytes.Buffer)
	binary.Write(timestampBinBuffer, binary.BigEndian, timestamp.Unix())

	timestampBin := timestampBinBuffer.Bytes()
	return timestampBin
}

// Encodes a port to a byte slice of size 2. Be careful to supply it a valid uin16 number.
func encodePort(port uint16) []byte {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, port)
	return buff
}

// Encodes the duration to a byte slice.
func encodeDuration(dur uint16) []byte {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, dur)
	return buff
}
