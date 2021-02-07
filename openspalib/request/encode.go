package request

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/greenstatic/openspalib/tools"
	"net"
	"strings"
	"time"
)

// Encodes the packet payload according to the OpenSPA specification
// for request packet payload.
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

	// Client device ID - 128 bits = 16 bytes
	const clientDeviceIdSize = 16 // bytes
	clientDeviceId, err := encodeClientDeviceID(p.ClientDeviceID)
	if err != nil {
		return nil, err
	}

	for i := 0; i < clientDeviceIdSize; i++ {
		payloadBuff[offset+i] = clientDeviceId[i]
	}

	offset += clientDeviceIdSize

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

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	payloadBuff[offset] = p.SignatureMethod
	offset += signatureMethodSize

	// Misc Field - 8 bits = 1 byte
	// X0000000 <- misc field, where X is Client NAT field

	const miscFieldsSize = 1 // byte
	miscField := encodeMiscField(p.ClientBehindNat)
	payloadBuff[offset] = miscField
	offset += miscFieldsSize

	// Reserved - 16 bits = 2 bytes
	const reservedSize = 2 // bytes

	// set all values to 0
	for i := 0; i < reservedSize; i++ {
		payloadBuff[offset+i] = 0
	}

	offset += reservedSize

	// Client Public IP - 128 bits = 16 bytes - could be IPv4 or IPv6
	const clientPublicIPSize = 16 // bytes
	clientPublicIP, err := IPAddressToBinIP(p.ClientPublicIP)
	if err != nil {
		return nil, err
	}

	for i := 0; i < clientPublicIPSize; i++ {
		payloadBuff[offset+i] = clientPublicIP[i]
	}

	offset += clientPublicIPSize

	// Server Public IP - 128 bit = 16 bytes - could be IPv4 or IPv6
	const serverPublicIPSize = 16 //bytes
	serverPublicIP, err := IPAddressToBinIP(p.ServerPublicIP)
	if err != nil {
		return nil, err
	}

	for i := 0; i < serverPublicIPSize; i++ {
		payloadBuff[offset+i] = serverPublicIP[i]
	}

	offset += serverPublicIPSize

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

// Encodes the client devices ID, which should be a UUID v4 in such a way that
// we remove the dashes and return a byte slice. Accepts also a client device ID
// without dashes (as long as it's a UUID).
func encodeClientDeviceID(clientDeviceId string) ([]byte, error) {

	const size = 16             // bytes
	const stringSize = size * 2 // two characters (encoded as hex) from a string represent a single byte
	const noDashes = 4

	// checks if the size is appropriate for a string with and without dashes for a UUID v4
	if len(clientDeviceId) != stringSize && len(clientDeviceId) != stringSize+noDashes {
		return nil, errors.New("client device ID is not the appropriate size")
	}

	// remove dashes from the client device ID string
	clientDeviceIdStrTmp := strings.Split(clientDeviceId, "-")
	clientDeviceIdStr := strings.Join(clientDeviceIdStrTmp, "")
	buff, err := hex.DecodeString(clientDeviceIdStr)

	// the reason we didn't directly return hex.DecodeString() is because in case of an
	// error the function still returns the byte slice that it was successfully able to
	// convert. But we wished to return an empty one in the event of an error.
	if err != nil {
		return []byte{}, err
	}
	return buff, nil
}

// Encodes a port to a byte slice of size 2. Be careful to supply it a valid uin16 number.
func encodePort(port uint16) []byte {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, port)
	return buff
}

// Encodes the parameters set in the Misc field.
func encodeMiscField(behindNAT bool) byte {
	// X0000000 <- final byte, where X is Client NAT field

	var finalByte byte = 0x0

	// Client is behind NAT - 1 bit
	var clientBehindNat byte = 0x0 // BIN: 0000 0000 <- not behind nat

	if behindNAT {
		clientBehindNat = 0x80 // BIN: 1000 0000 <- behind nat
	}

	finalByte = finalByte | clientBehindNat

	// the remanding bits are reserved but not in use
	return finalByte
}

// Returns a byte slice 16 bytes long which represents an IPv4 or IPv6 address (depending on
// the inputted IP address). In case the inputted address is IPv4 we will follow RFC 4291
// "IPv4-Mapped IPv6 address" specification for the binary representation of the address.
func IPAddressToBinIP(ip net.IP) ([]byte, error) {

	ipIs6, err := tools.IsIPv6(ip.String())

	if err != nil {
		return nil, errors.New("failed to check if ip is an IPv6 address")
	}

	if ipIs6 {
		return ip, nil
	}

	// The address needs to be formatted according to RFC4291. Note the size is of an IPv6 address
	// since we are placing the IPv4 address inside an IPv6 address.
	const ipv4Length = 16 // bytes
	ipv4 := make([]byte, ipv4Length)
	ipv4Counter := 0

	// make the first 10 bytes (80 bits) 0
	const zeroedByteLength = 10
	for i := 0; i < zeroedByteLength; i++ {
		ipv4[ipv4Counter] = 0x0
		ipv4Counter++
	}

	// set the next two bytes (11th and 12th byte) to FF
	ipv4[ipv4Counter] = 0xFF
	ipv4Counter++
	ipv4[ipv4Counter] = 0xFF
	ipv4Counter++

	// internally net.IP saves an IPv4 address either as a 4 or 16 byte slice
	IPOffset := 0
	if len(ip) == 16 {
		IPOffset = 12
	}

	for i := 0; i < 4; i++ {
		ipv4[ipv4Counter] = ip[IPOffset+i]
		ipv4Counter++
	}

	return ipv4, nil
}
