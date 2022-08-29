package header

import (
	"errors"
)

// Converts a byte slice into a header struct according to the OpenSPA specification.
// Does not validate any binary according to the specification it merely does a dumb
// mapping of binary to the OpenSPA specification.
func binaryDecode(data []byte) (header Header, err error) {

	if len(data) < Size {
		return Header{}, errors.New("data too short to be an openspa header")
	}

	headerBin := data[:Size]
	/// Version (V) 4 bits || Type of Packet (T) 1 bit || Reserved (R) 5 bits || Encryption Method (E) 6 bits

	// Version
	// VVVV TRRR >> 4 =
	// 0000 VVVV
	ver := uint8(headerBin[0x0] >> 4)

	// Type of Packet
	//   0000 1111  <- 0x0F
	// & VVVV TRRR
	//	-----------
	//   0000 TRRR >> 3 =
	//   0000 000T
	typeOfPacket := (headerBin[0x0] & 0x0F) >> 3

	isRequest := typeOfPacket == 0

	// Encryption Method
	// 	 0011 1111	<- 0x3f
	// & RREE EEEE
	// ------------
	//   00EE EEEE
	encryptionMethod := 0x3F & headerBin[0x1]

	return Header{ver, isRequest, encryptionMethod}, nil
}
