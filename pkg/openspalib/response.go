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

type ResponseData struct {
	TransactionID uint8

	ClientUUID string

	TargetProtocol  InternetProtocolNumber
	TargetIP        net.IP
	TargetPortStart int
	TargetPortEnd   int

	Duration time.Duration
}

type ResponseExtendedData struct {
	Nonce []byte
}

type Response struct {
	c crypto.CipherSuite

	Header Header
	Body   tlv.Container

	// Metadata is not actually sent, but it is passed to the CipherSuite implementation, so we can provide additional
	// data that can be used by CipherSuite implementation for security purposes. This data is not packed into OpenSPA
	// request/responses, it is merely passed along various subsystems.
	Metadata tlv.Container
}

func NewResponse(d ResponseData, c crypto.CipherSuite) (*Response, error) {
	if c == nil {
		return nil, ErrCipherSuiteRequired
	}

	r := &Response{}
	r.c = c

	r.Header = NewHeader(ResponsePDU, c.CipherSuiteID())
	r.Header.TransactionID = d.TransactionID

	ed, err := r.generateExtendedData()
	if err != nil {
		return nil, errors.Wrap(err, "response extended data generation")
	}

	r.Body = tlv.NewContainer()
	if err = r.bodyCreate(r.Body, d, ed); err != nil {
		return nil, errors.Wrap(err, "body create")
	}

	r.Metadata = tlv.NewContainer()
	if err := r.metadataCreate(r.Metadata, d); err != nil {
		return nil, errors.Wrap(err, "metadata create")
	}

	return r, nil
}

func (r *Response) Marshal() ([]byte, error) {
	header, err := r.Header.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "header marshal")
	}

	ec, err := r.c.Secure(header, r.Body, r.Metadata)
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

func (r *Response) generateExtendedData() (ResponseExtendedData, error) {
	ed := ResponseExtendedData{}

	ed.Nonce = make([]byte, NonceSize)

	n, err := rand.Read(ed.Nonce)
	if err != nil {
		return ResponseExtendedData{}, errors.New("nonce generation")
	}
	if n != NonceSize {
		return ResponseExtendedData{}, errors.New("invalid nonce size random bytes")
	}

	return ed, nil
}

func (r *Response) bodyCreate(c tlv.Container, d ResponseData, ed ResponseExtendedData) error {
	if err := TargetProtocolToContainer(c, d.TargetProtocol); err != nil {
		return errors.Wrap(err, "protocol to container")
	}

	if isIPv4(d.TargetIP) {
		if err := TargetIPv4ToContainer(c, d.TargetIP); err != nil {
			return errors.Wrap(err, "target ipv4 to container")
		}
	} else {
		if err := TargetIPv6ToContainer(c, d.TargetIP); err != nil {
			return errors.Wrap(err, "target ipv6 to container")
		}
	}

	if err := TargetPortStartToContainer(c, d.TargetPortStart); err != nil {
		return errors.Wrap(err, "port start to container")
	}

	if err := TargetPortEndToContainer(c, d.TargetPortEnd); err != nil {
		return errors.Wrap(err, "port end to container")
	}

	if err := DurationToContainer(c, d.Duration); err != nil {
		return errors.Wrap(err, "duration to container")
	}

	if err := NonceToContainer(c, ed.Nonce); err != nil {
		return errors.Wrap(err, "nonce to container")
	}

	return nil
}

func (r *Response) metadataCreate(c tlv.Container, d ResponseData) error {
	if err := ClientUUIDToContainer(c, d.ClientUUID); err != nil {
		return errors.Wrap(err, "client uuid to container")
	}

	return nil
}

func ResponseUnmarshal(b []byte, cs crypto.CipherSuite) (*Response, error) {
	if len(b) < HeaderLength {
		return nil, errors.New("too short to be response")
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

	r := &Response{
		c:      cs,
		Header: header,
		Body:   body,
	}

	return r, nil
}
