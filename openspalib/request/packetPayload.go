package request

import (
	"strconv"

	"github.com/greenstatic/openspa/openspalib/tools"
)

// Returns the timestamp as a string
func (pp *packetPayload) TimestampToString() string {
	return strconv.FormatUint(uint64(pp.Timestamp.Unix()), 10)
}

// Returns the protocol as a string
func (pp *packetPayload) ProtocolToString() string {
	return tools.ConvertProtoByteToStr(pp.Protocol)
}

// Returns the start port as a string
func (pp *packetPayload) StartPortToString() string {
	return strconv.Itoa(int(pp.StartPort))
}

// Returns the end port as a string
func (pp *packetPayload) EndPortToString() string {
	return strconv.Itoa(int(pp.EndPort))
}

// Returns the signature method as a string
func (pp *packetPayload) SignatureMethodToString() string {
	return tools.ConvertSignatureMethodByteToStr(pp.SignatureMethod)
}

// Returns the behind nat flag as a string (1=true, 0=false)
func (pp *packetPayload) BehindNATToString() string {
	if pp.ClientBehindNat {
		return "1"
	}
	return "0"
}
