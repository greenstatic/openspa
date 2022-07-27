package openspalib

import (
	"bytes"
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
)

type RequestData struct {
	TransactionId uint8
	Timestamp     time.Time

	Protocol  InternetProtocolNumber
	PortStart int
	PortEnd   int

	ClientIP net.IP
	ServerIP net.IP
}

type Request struct {
	c crypto.CipherSuite

	Header Header
	Body   tlv.Container
}

func NewRequest(d RequestData, c crypto.CipherSuite) (*Request, error) {
	if c == nil {
		return nil, ErrCipherSuiteRequired
	}

	r := &Request{}
	r.c = c

	r.Header = NewHeader(RequestPDU, c.CipherSuiteId())
	r.Header.TransactionId = d.TransactionId

	r.Body = tlv.NewContainerStub()

	return r, nil
}

func (r *Request) Marshal() ([]byte, error) {
	header, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	ec, err := r.c.Secure(header, r.Body)
	if err != nil {
		return nil, err
	}

	b := bytes.Buffer{}
	b.Write(header)
	b.Write(ec.Bytes())

	return b.Bytes(), nil
}

func RequestUnmarshal(b []byte) (*Request, error) {
	return nil, nil
}
