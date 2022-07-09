package openspalib

import (
	"net"
	"time"
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
	c CipherSuite

	Header Header
	Body   Container
}

func NewRequest(d RequestData, c CipherSuite) (*Request, error) {
	if c == nil {
		return nil, ErrCipherSuiteRequired
	}

	r := &Request{}
	r.c = c

	r.Header = NewHeader(RequestPDU, c.CipherSuiteId())
	r.Header.TransactionId = d.TransactionId

	r.Body = NewContainerStub()

	return r, nil
}

func (r *Request) Marshal() ([]byte, error) {
	header, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	body, err := r.c.Secure(r.Body.Bytes())
	if err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

func RequestUnmarshal(b []byte) (*Request, error) {
	return nil, nil
}
