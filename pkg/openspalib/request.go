package openspalib

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

type RequestData struct {
	TransactionId uint8
	ClientUUID    string

	Protocol  InternetProtocolNumber
	PortStart int
	PortEnd   int

	ClientIP net.IP
	ServerIP net.IP
}

type RequestExtendedData struct {
	Timestamp time.Time
	Nonce     []byte
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

	ed, err := r.generateRequestExtendedData()
	if err != nil {
		return nil, errors.Wrap(err, "request extended data generation")
	}

	r.Body, err = r.bodyCreate(d, ed)
	if err != nil {
		return nil, errors.Wrap(err, "body create")
	}

	return r, nil
}

func (r *Request) generateRequestExtendedData() (RequestExtendedData, error) {
	ed := RequestExtendedData{}

	ed.Timestamp = time.Now()
	ed.Nonce = make([]byte, NonceSize)

	n, err := rand.Read(ed.Nonce)
	if err != nil {
		return RequestExtendedData{}, errors.New("nonce generation")
	}
	if n != NonceSize {
		return RequestExtendedData{}, errors.New("invalid nonce size random bytes")
	}

	return ed, nil
}

func (r *Request) bodyCreate(d RequestData, ed RequestExtendedData) (tlv.Container, error) {
	c := tlv.NewContainer()

	if err := TimestampToContainer(c, ed.Timestamp); err != nil {
		return nil, errors.Wrap(err, "timestamp to container")
	}

	if err := ClientDeviceUUIDToContainer(c, d.ClientUUID); err != nil {
		return nil, errors.Wrap(err, "client uuid to container")
	}

	if err := ProtocolToContainer(c, d.Protocol); err != nil {
		return nil, errors.Wrap(err, "protocol to container")
	}

	if err := PortStartToContainer(c, d.PortStart); err != nil {
		return nil, errors.Wrap(err, "port start to container")
	}

	if err := PortEndToContainer(c, d.PortEnd); err != nil {
		return nil, errors.Wrap(err, "port end to container")
	}

	if isIPv4(d.ClientIP) {
		if err := ClientIPv4ToContainer(c, d.ClientIP); err != nil {
			return nil, errors.Wrap(err, "client ipv4 to container")
		}

	} else {
		if err := ClientIPv6ToContainer(c, d.ClientIP); err != nil {
			return nil, errors.Wrap(err, "client ipv6 to container")
		}
	}

	if isIPv4(d.ServerIP) {
		if err := ServerIPv4ToContainer(c, d.ServerIP); err != nil {
			return nil, errors.Wrap(err, "server ipv4 to container")
		}

	} else {
		if err := ServerIPv6ToContainer(c, d.ServerIP); err != nil {
			return nil, errors.Wrap(err, "server ipv6 to container")
		}
	}

	if err := NonceToContainer(c, ed.Nonce); err != nil {
		return nil, errors.Wrap(err, "nonce to container")
	}

	return c, nil
}

func (r *Request) Marshal() ([]byte, error) {
	header, err := r.Header.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "header marshal")
	}

	ec, err := r.c.Secure(header, r.Body)
	if err != nil {
		return nil, errors.Wrap(err, "secure")
	}

	b := bytes.Buffer{}
	b.Write(header)
	b.Write(ec.Bytes())

	return b.Bytes(), nil
}

func RequestUnmarshal(b []byte, cs crypto.CipherSuite) (*Request, error) {
	if len(b) < HeaderLength {
		return nil, errors.New("too short to be request")
	}

	headerB := b[:HeaderLength]

	header, err := UnmarshalHeader(headerB)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal header")
	}

	c, err := tlv.UnmarshalTLVContainer(b[HeaderLength:])
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal tlv container")
	}

	body, err := cs.Unlock(headerB, c)
	if err != nil {
		return nil, errors.Wrap(err, "crypto unlock")
	}

	r := &Request{
		c:      cs,
		Header: header,
		Body:   body,
	}

	return r, nil
}
