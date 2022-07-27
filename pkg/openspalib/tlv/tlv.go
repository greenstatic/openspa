package tlv

type Container interface {
	GetByte(key uint8) (b byte, exists bool)
	GetBytes(key uint8) (b []byte, exists bool)

	SetByte(key uint8, value byte)
	SetBytes(key uint8, value []byte)

	Remove(key uint8)

	Bytes() []byte

	// Size returns the length of the byte slice or buffer
	//Size() int

	// NoEntries returns the number of nodes in the container
	NoEntries() int

	// Merge merges the input parameter container with the container on which it is called and returns the merged
	// container. All data is copied, no modifications are made to either input containers.
	// TODO - ?
	//Merge(c Container) (Container, error)
}
