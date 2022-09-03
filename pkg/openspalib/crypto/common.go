package crypto

import (
	"crypto"
	"errors"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
)

// PublicKeyLookuper is used when we need to get the client's public key based on their clientUUID. The client's public
// key will be used to encrypt OpenSPA responses and verify signatures from OpenSPA requests. If the client is not
// authorized, this function should still return their key, since the authentication step is performed separately.
type PublicKeyLookuper interface {
	LookupPublicKey(clientUUID string) (crypto.PublicKey, error)
}

type PublicKeyResolver interface {
	PublicKey(packet, meta tlv.Container) (crypto.PublicKey, error)
}

func PaddingPKCS7(data []byte, blockSize int) ([]byte, error) {
	if blockSize >= 256 || blockSize < 0 {
		return nil, errors.New("invalid block size")
	}

	size := blockSize - (len(data) % blockSize)
	if size == 0 {
		size = blockSize
	}

	padding := make([]byte, size)

	for i := 0; i < size; i++ {
		padding[i] = byte(size)
	}

	dataPadded := make([]byte, len(data), len(data)+size)
	copy(dataPadded, data)
	dataPadded = append(dataPadded, padding...)

	return dataPadded, nil
}

func PaddingPKCS7Remove(data []byte, blockSize int) ([]byte, error) {
	if blockSize >= 256 || blockSize < 0 {
		return nil, errors.New("invalid block size")
	}

	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	s := int(data[len(data)-1])
	if s > len(data) {
		return nil, errors.New("padding length is larger than input data slice")
	}

	pIdx := len(data) - s

	for i := len(data) - 1; i >= pIdx; i-- {
		if int(data[i]) != s {
			return nil, errors.New("padding value is not consistent")
		}
	}

	return data[:pIdx], nil
}
