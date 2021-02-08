package openspalib

// Returns if the specified byte is present in the byte slice.
func byteInSlice(elm byte, slice []byte) bool {
	for _, i := range slice {
		if elm == i {
			return true
		}
	}

	return false
}
