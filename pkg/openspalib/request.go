package openspalib

import (
	"bytes"
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

	r.Body, err = RequestDataToContainer(d, ed)
	if err != nil {
		return nil, errors.Wrap(err, "body create")
	}

	return r, nil
}

//nolint:unparam
func (r *Request) generateRequestExtendedData() (RequestExtendedData, error) {
	ed := RequestExtendedData{}

	ed.Timestamp = time.Now()

	return ed, nil
}

func (r *Request) Marshal() ([]byte, error) {
	header, err := r.Header.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "header marshal")
	}

	ec, err := r.c.Secure(header, r.Body, nil)
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

func RequestDataToContainer(d RequestData, ed RequestExtendedData) (tlv.Container, error) {
	packet := tlv.NewContainer()
	firewall := tlv.NewContainer()

	if err := TimestampToContainer(packet, ed.Timestamp); err != nil {
		return nil, errors.Wrap(err, "timestamp to container")
	}

	if err := ClientUUIDToContainer(packet, d.ClientUUID); err != nil {
		return nil, errors.Wrap(err, "client uuid to container")
	}

	if err := TargetProtocolToContainer(firewall, d.TargetProtocol); err != nil {
		return nil, errors.Wrap(err, "target protocol to container")
	}

	if err := TargetPortStartToContainer(firewall, d.TargetPortStart); err != nil {
		return nil, errors.Wrap(err, "target port start to container")
	}

	if err := TargetPortEndToContainer(firewall, d.TargetPortEnd); err != nil {
		return nil, errors.Wrap(err, "target port end to container")
	}

	if isIPv4(d.ClientIP) {
		if err := ClientIPv4ToContainer(firewall, d.ClientIP); err != nil {
			return nil, errors.Wrap(err, "client ipv4 to container")
		}
	} else {
		if err := ClientIPv6ToContainer(firewall, d.ClientIP); err != nil {
			return nil, errors.Wrap(err, "client ipv6 to container")
		}
	}

	if isIPv4(d.TargetIP) {
		if err := TargetIPv4ToContainer(firewall, d.TargetIP); err != nil {
			return nil, errors.Wrap(err, "target ipv4 to container")
		}
	} else {
		if err := TargetIPv6ToContainer(firewall, d.TargetIP); err != nil {
			return nil, errors.Wrap(err, "target ipv6 to container")
		}
	}

	if err := TLVToContainer(packet, firewall, FirewallKey); err != nil {
		return nil, errors.Wrap(err, "firewall tlv to packet container")
	}

	return packet, nil
}

type RequestFirewallData struct {
	Timestamp  time.Time
	ClientUUID string

	ClientIP        net.IP
	TargetProtocol  InternetProtocolNumber
	TargetIP        net.IP
	TargetPortStart int
	TargetPortEnd   int
}

func RequestFirewallDataFromContainer(c tlv.Container) (RequestFirewallData, error) {
	fd := RequestFirewallData{}

	var err error

	fd.Timestamp, err = TimestampFromContainer(c)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "timestamp from container")
	}

	fd.ClientUUID, err = ClientUUIDFromContainer(c)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "client uuid from container")
	}

	fwc, err := TLVFromContainer(c, FirewallKey)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "firewall tlv from container")
	}

	fd.TargetProtocol, err = TargetProtocolFromContainer(fwc)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "target protocol from container")
	}

	fd.TargetPortStart, err = TargetPortStartFromContainer(fwc)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "target port start tlv from container")
	}

	fd.TargetPortEnd, err = TargetPortEndFromContainer(fwc)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "target port end tlv from container")
	}

	fd.ClientIP, err = ClientIPFromContainer(fwc)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "client ip from container")
	}

	fd.TargetIP, err = TargetIPFromContainer(fwc)
	if err != nil {
		return RequestFirewallData{}, errors.Wrap(err, "target ip from container")
	}

	return fd, nil
}
