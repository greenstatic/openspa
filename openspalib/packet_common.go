package openspalib

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"strings"
	"time"
)

// Encodes the client's device ID, which should be a UUID v4 in such a way that we remove the dashes and return a byte
// slice. Accepts also a client device ID without dashes (as long as it's a UUID).
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

// Encodes a time.Time field into a unix 64-bit timestamp - 8 byte slice
func encodeTimestamp(timestamp time.Time) []byte {

	timestampBinBuffer := new(bytes.Buffer)
	binary.Write(timestampBinBuffer, binary.BigEndian, timestamp.Unix())

	timestampBin := timestampBinBuffer.Bytes()
	return timestampBin
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

// Encodes a port to a byte slice of size 2. Be careful to supply it a valid uin16 number.
func encodePort(port uint16) []byte {
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, port)
	return buff
}

// Decodes a 2-byte port. Port 0 is disallowed and will trigger an error.
func decodePort(data []byte, protocol InternetProtocolNumber) (uint16, error) {
	port := binary.BigEndian.Uint16(data)

	portCanBeZero := portCanBeZero(protocol)
	if !portCanBeZero && port == 0 {
		return 0, errors.New("port 0 is disallowed")
	}

	return port, nil
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

// Returns from the misc field byte data the parsed values of:
// * Client Behind NAT boolean
func decodeMiscField(data byte) (clientBehindNAT bool, err error) {
	clientBehindNatBin := data >> 7
	clientBehindNAT = int(clientBehindNatBin) != 0 // convert to bool
	return
}

// Decodes a byte signature method. Checks if the signature method is supported.
func decodeSignatureMethod(data byte) (SignatureMethod, error) {
	s := SignatureMethod(data)
	if !SignatureMethodIsSupported(s) {
		return 0, errors.New("unsupported signature method:" + fmt.Sprintf("%x", data))
	}

	return s, nil
}

// Returns a byte slice 16 bytes long which represents an IPv4 or IPv6 address (depending on the inputted IP address).
// In case the inputted address is IPv4 we will follow RFC 4291 "IPv4-Mapped IPv6 address" specification for the binary
// representation of the address.
func ipAddressToBinIP(ip net.IP) ([]byte, error) {
	ipIs6, err := isIPv6(ip.String())

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

// Returns a net.IP type from the provided byte slice. The inputted byte slice needs to be 16 bytes long and can be a
// IPv6 binary address or an IPv4 binary address mapped as an IPv6 address specified by RFC 4291
// "IPv4-Mapped IPv6 Address".
func binIPAddressToIP(binIp []byte) (net.IP, error) {
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

// Encodes the duration to a byte slice.
func encodeDuration(dur time.Duration) []byte {
	durSec := uint16(dur.Seconds())
	buff := make([]byte, 2)
	binary.BigEndian.PutUint16(buff, durSec)
	return buff
}

// Decodes a 2-byte duration slice.
func decodeDuration(data []byte) (time.Duration, error) {
	duration := binary.BigEndian.Uint16(data)
	t := time.Second * time.Duration(duration)
	return t, nil
}