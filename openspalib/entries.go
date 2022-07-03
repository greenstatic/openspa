package openspalib

import (
	"encoding/binary"
	"time"
)

func TimestampEncode(t time.Time) ([]byte, error) {
	b := make([]byte, 8)
	i := t.Unix()
	binary.BigEndian.PutUint64(b, uint64(i))
	return b, nil
}

func TimestampDecode(b []byte) (time.Time, error) {
	const timestampSize = 8 // bytes

	if len(b) != timestampSize {
		return time.Time{}, ErrInvalidBytes
	}

	i := binary.BigEndian.Uint64(b)
	t := time.Unix(int64(i), 0)

	return t.UTC(), nil
}

func ProtocolEncode(p InternetProtocolNumber) (byte, error) {
	return p.ToBin(), nil
}

func ProtocolDecode(b []byte) (InternetProtocolNumber, error) {
	const protocolSize = 1

	if len(b) != protocolSize {
		return InternetProtocolNumber(0), ErrInvalidBytes
	}

	return InternetProtocolNumber(b[0]), nil
}
