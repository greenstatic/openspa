package request

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/header"
	"github.com/greenstatic/openspalib/tools"
	"net"
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
			"raw request packet is too short to be an OpenSPA packet, length: %d bytes, expects at least: %d bytes (header+body unsigned)",
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

	// Client device ID - 128 bits = 16 bytes
	const clientDeviceIdSize = 16 //bytes
	clientDeviceID, err := decodeClientDeviceID(data[offset : offset+clientDeviceIdSize])
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.ClientDeviceID = clientDeviceID
	offset += clientDeviceIdSize

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

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	sigMethod, err := decodeSignatureMethod(data[offset])
	if err != nil {
		return packetPayload{}, nil, err
	}

	p.SignatureMethod = sigMethod
	offset += signatureMethodSize

	// Misc Field - 8 bits = 1 byte
	// X0000000 <- misc field, where X is Client NAT field

	const miscFieldsSize = 1 // byte
	clientNAT, err := decodeMiscField(data[offset])

	p.ClientBehindNat = clientNAT
	offset += miscFieldsSize

	// Reserved - 16 bits = 2 bytes
	const reservedSize = 2 // bytes
	offset += reservedSize

	// Client Public IP - 128 bits = 16 bytes - could be IPv4 or IPv6
	const clientPublicIPSize = 16 // bytes
	clientIP, err := BinIPAddressToIP(data[offset : offset+clientPublicIPSize])

	p.ClientPublicIP = clientIP
	offset += clientPublicIPSize

	// Server Public IP - 128 bit = 16 bytes - could be IPv4 or IPv6
	const serverPublicIPSize = 16 //bytes
	serverIP, err := BinIPAddressToIP(data[offset : offset+serverPublicIPSize])

	p.ServerPublicIP = serverIP
	offset += serverPublicIPSize

	// Signature - max 9296 bits = max 1162 bytes
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

// Decodes a 16-byte client device ID byte slice into a string
func decodeClientDeviceID(data []byte) (string, error) {
	clientDeviceIdDashless := hex.EncodeToString(data)

	// add dashes in the format 8-4-4-4-12
	clientDeviceId := ""

	dashOffset := []int{8, 4, 4, 4, 12}
	dashOffsetCount := 0
	for pos, char := range clientDeviceIdDashless {

		if dashOffsetCount < len(dashOffset)-1 && pos == dashOffset[dashOffsetCount] {
			dashOffsetCount++
			dashOffset[dashOffsetCount] += pos
			clientDeviceId += "-"
		}

		clientDeviceId += string(char)
	}

	return clientDeviceId, nil
}

// Decodes a 2-byte port. Port 0 is disallowed and will trigger
// an error.
func decodePort(data []byte, protocol byte) (uint16, error) {
	port := binary.BigEndian.Uint16(data)

	portCanBeZero := tools.PortCanBeZero(protocol)
	if !portCanBeZero && port == 0 {
		return 0, errors.New("port 0 is disallowed")
	}

	return port, nil
}

// Decodes a byte signature method. Checks if the signature method
// is supported.
func decodeSignatureMethod(data byte) (byte, error) {
	if !tools.ElementInSlice(data, openspalib.SupportedSignatureMethods()) {
		return 0, errors.New("unsupported signature method:" + fmt.Sprintf("%x", data))
	}

	return data, nil
}

// Returns from the misc field byte data the parsed values of:
// * Client Behind NAT boolean
func decodeMiscField(data byte) (clientBehindNAT bool, err error) {
	clientBehindNatBin := data >> 7
	clientBehindNAT = int(clientBehindNatBin) != 0 // convert to bool
	return
}

// Returns a net.IP type from the provided byte slice. The inputted byte slice needs to be
// 16 bytes long and can be a IPv6 binary address or an IPv4 binary address mapped as an IPv6
// address specified by RFC 4291 "IPv4-Mapped IPv6 Address".
func BinIPAddressToIP(binIp []byte) (net.IP, error) {

	if len(binIp) != 16 {
		return nil, errors.New("provided byte slice is not of length 16")
	}

	// Detect if the binary address is IPv4 as specified in RFC 4291 "IPv4-Mapped IPv6 Address"
	couldBeIPv4 := true
	byteCounter := 0

	// check first 10 bytes (80 bits) if they are 0's
	const zeroedByteLength = 10

	for i := 0; i < zeroedByteLength; i++ {
		if binIp[i] != 0 {
			couldBeIPv4 = false
			break
		}
	}

	byteCounter += zeroedByteLength

	// continue to check
	// check if the 11th and 12th byte is set to FF
	const ffedByteLength = 2
	if couldBeIPv4 && (binIp[byteCounter+ffedByteLength-1] == 0xFF && binIp[byteCounter+ffedByteLength] == 0xFF) {
		// address is IPv4
		byteCounter += ffedByteLength
		binIpv4 := binIp[byteCounter:] // should be 4 bytes
		return net.IPv4(binIpv4[0], binIpv4[1], binIpv4[2], binIpv4[3]), nil
	}

	// Looks like it's an IPv6 address
	return net.IP(binIp), nil
}
