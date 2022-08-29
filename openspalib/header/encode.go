package header

// Converts a a header struct into a byte slice according to the OpenSPA specification.
// Does not validate any binary according to the specification it merely does a dumb
// mapping of binary to the OpenSPA specification. It will overflow if given values that
// are too large.
func (header *Header) binaryEncode() []byte {

	buffer := make([]byte, Size)

	// Version
	// 0000 VVVV << 4
	// VVVV TRRR
	buffer[0x0] = header.Version << 4

	// Type of Packet
	if !header.IsRequest {
		// Request packet
		//   0000 1000  <- 0x08
		// | VVVV TRRR ... T=1
		//	-----------
		//   VVVV T000
		buffer[0x0] = buffer[0x0] | 0x08
	}

	// Encryption Method
	// 	 0011 1111	<- 0x3f
	// & RREE EEEE
	// ------------
	//   00EE EEEE
	buffer[0x1] = 0x3F & header.EncryptionMethod

	return buffer
}
