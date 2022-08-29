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
	TransactionID uint8
	ClientUUID    string

	ClientIP net.IP

	TargetProtocol  InternetProtocolNumber
	TargetIP        net.IP
	TargetPortStart int
	TargetPortEnd   int
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

	r.Header = NewHeader(RequestPDU, c.CipherSuiteID())
	r.Header.TransactionID = d.TransactionID

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

	if err := ClientUUIDToContainer(c, d.ClientUUID); err != nil {
		return nil, errors.Wrap(err, "client uuid to container")
	}

	if err := TargetProtocolToContainer(c, d.TargetProtocol); err != nil {
		return nil, errors.Wrap(err, "target protocol to container")
	}

	if err := TargetPortStartToContainer(c, d.TargetPortStart); err != nil {
		return nil, errors.Wrap(err, "target port start to container")
	}

	if err := TargetPortEndToContainer(c, d.TargetPortEnd); err != nil {
		return nil, errors.Wrap(err, "target port end to container")
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

	if isIPv4(d.TargetIP) {
		if err := TargetIPv4ToContainer(c, d.TargetIP); err != nil {
			return nil, errors.Wrap(err, "target ipv4 to container")
		}
	} else {
		if err := TargetIPv6ToContainer(c, d.TargetIP); err != nil {
			return nil, errors.Wrap(err, "target ipv6 to container")
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

	buf := bytes.Buffer{}
	buf.Write(header)
	buf.Write(ec.Bytes())

	b := buf.Bytes()

	if len(b) > MaxPDUSize {
		return b, ErrPDUTooLarge
	}

	return b, nil
}

func RequestUnmarshal(b []byte, cs crypto.CipherSuite) (*Request, error) {
	if len(b) < HeaderLength {
		return nil, errors.New("too short to be request")
	}

	if len(b) == HeaderLength {
		return nil, errors.New("body is empty")
	}

	headerBytes := b[:HeaderLength]
	bodyBytes := b[HeaderLength:]

	header, err := UnmarshalHeader(headerBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal header")
	}

	c, err := tlv.UnmarshalTLVContainer(bodyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal tlv container")
	}

	body, err := cs.Unlock(headerBytes, c)
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
