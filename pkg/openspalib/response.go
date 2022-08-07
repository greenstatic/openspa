package openspalib

import (
	"bytes"
	"crypto/rand"
	"time"

	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

type ResponseData struct {
	TransactionId uint8

	TargetProtocol  InternetProtocolNumber
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
}

func NewResponse(d ResponseData, c crypto.CipherSuite) (*Response, error) {
	if c == nil {
		return nil, ErrCipherSuiteRequired
	}

	r := &Response{}
	r.c = c

	r.Header = NewHeader(ResponsePDU, c.CipherSuiteId())
	r.Header.TransactionId = d.TransactionId

	ed, err := r.generateExtendedData()
	if err != nil {
		return nil, errors.Wrap(err, "response extended data generation")
	}

	r.Body, err = r.bodyCreate(d, ed)
	if err != nil {
		return nil, errors.Wrap(err, "body create")
	}

	return r, nil
}

func (r *Response) Marshal() ([]byte, error) {
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

func (r *Response) bodyCreate(d ResponseData, ed ResponseExtendedData) (tlv.Container, error) {
	c := tlv.NewContainer()

	if err := TargetProtocolToContainer(c, d.TargetProtocol); err != nil {
		return nil, errors.Wrap(err, "protocol to container")
	}

	if err := TargetPortStartToContainer(c, d.TargetPortStart); err != nil {
		return nil, errors.Wrap(err, "port start to container")
	}

	if err := TargetPortEndToContainer(c, d.TargetPortEnd); err != nil {
		return nil, errors.Wrap(err, "port end to container")
	}

	if err := DurationToContainer(c, d.Duration); err != nil {
		return nil, errors.Wrap(err, "duration to container")
	}

	if err := NonceToContainer(c, ed.Nonce); err != nil {
		return nil, errors.Wrap(err, "nonce to container")
	}

	if err := NonceToContainer(c, ed.Nonce); err != nil {
		return nil, errors.Wrap(err, "nonce to container")
	}

	return c, nil
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
