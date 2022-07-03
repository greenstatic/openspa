package openspalib_old

import (
	"bytes"
	"net"
	"time"

	"github.com/pkg/errors"
)

const (
	nonceSize = 3
)

// Request represents an OpenSPA Request. Either create a Request struct and the appropriate sub-structs or use the
// NewRequest function to apply the default values for various Request fields (e.g. timestamp, protocol version, etc.).
type Request struct {
	Header Header

	// Body
	AdditionalPlaintextData TLVContainer
	SecureContainer         RequestSecureContainer
}

// RequestSecureContainer is data that will be encrypted in the OpenSPA Request.
type RequestSecureContainer struct {
	ClientDeviceUUID string
	Timestamp        time.Time
	Nonce            []byte

	Protocol  InternetProtocolNumber
	PortStart uint16
	PortEnd   uint16

	ClientPublicIPv4 net.IP
	ClientPublicIPv6 net.IP
	IPInfo           IPInfo

	ServerPublicIPv4 net.IP
	ServerPublicIPv6 net.IP

	AdditionalSecureData TLVContainer

	Signature []byte
}

// RequestData is used with NewRequest() to create all the appropriate structs for the OpenSPA Request.
type RequestData struct {
	ClientDeviceUUID string

	Protocol  InternetProtocolNumber
	PortStart uint16
	PortEnd   uint16

	ClientPublicIPv4 net.IP
	ClientPublicIPv6 net.IP
	ClientBehindNat  bool

	ServerPublicIPv4 net.IP
	ServerPublicIPv6 net.IP

	AdditionalSecureData    TLVContainer
	AdditionalPlaintextData TLVContainer
}

func NewRequest(data RequestData) Request {
	r := Request{}

	r.Header = Header{
		TransactionId: randomByteSlice(1)[0],
	}
	r.Header.SetVersion(Version)
	r.Header.SetType(PDURequestType)
	r.AdditionalPlaintextData = data.AdditionalPlaintextData

	r.SecureContainer = RequestSecureContainer{
		ClientDeviceUUID: data.ClientDeviceUUID,
		Timestamp:        time.Now(),
		Protocol:         data.Protocol,
		PortStart:        data.PortStart,
		PortEnd:          data.PortEnd,
		ClientPublicIPv4: data.ClientPublicIPv4,
		ClientPublicIPv6: data.ClientPublicIPv6,
		ServerPublicIPv4: data.ServerPublicIPv4,
		ServerPublicIPv6: data.ServerPublicIPv6,
		IPInfo: IPInfo{
			ClientBehindNAT: data.ClientBehindNat,
		},
		Nonce:                randomByteSlice(nonceSize),
		AdditionalSecureData: data.AdditionalSecureData,
	}

	return r
}

func (r *Request) SignAndEncrypt(c CipherSuite) ([]byte, error) {
	r.Header.CipherSuiteId = c.CipherSuiteId()

	header, err := r.Header.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "header encode")
	}

	if err := r.Validate(); err != nil {
		return nil, errors.Wrap(err, "validation error")
	}

	signature, err := r.sign(c)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	r.SecureContainer.Signature = signature

	secureContainer, err := r.SecureContainer.Container()
	if err != nil {
		return nil, errors.Wrap(err, "secureContainer container")
	}

	ciphertext, err := c.Encrypt(secureContainer.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "encrypt secure container")
	}

	tlv := NewEmptyTLVContainer()
	tlv.SetBytes(TypeEncryptedContainer.Uint16(), ciphertext)
	if r.AdditionalPlaintextData != nil {
		tlv.SetBytes(TypeContainer.Uint16(), r.AdditionalPlaintextData.Bytes())
	}

	b := bytes.NewBuffer(header)
	_, err = tlv.BytesBuffer().WriteTo(b)
	if err != nil {
		return nil, errors.Wrap(err, "buffer write")
	}

	return b.Bytes(), nil
}

func (r *Request) SignatureData() ([]byte, error) {
	buf := bytes.Buffer{}

	h, err := r.Header.Encode()
	if err != nil {
		return nil, errors.Wrap(err, "header encoding")
	}
	buf.Write(h)

	if r.AdditionalPlaintextData != nil {
		_, err = r.AdditionalPlaintextData.BytesBuffer().WriteTo(&buf)
		if err != nil {
			return nil, errors.Wrap(err, "additional plaintext data write")
		}
	}

	secureContainer, err := r.SecureContainer.Container()
	if err != nil {
		return nil, errors.Wrap(err, "secure container")
	}

	_, err = secureContainer.BytesBuffer().WriteTo(&buf)
	if err != nil {
		return nil, errors.Wrap(err, "secure container data write")
	}

	return buf.Bytes(), nil
}

func (r *Request) sign(c CipherSuite) ([]byte, error) {
	signData, err := r.SignatureData()
	if err != nil {
		return nil, errors.Wrap(err, "signature data")
	}

	signature, err := c.Sign(signData)
	if err != nil {
		return nil, errors.Wrap(err, "sign")
	}

	return signature, nil
}

func (r *Request) Validate() error {
	// TODO
	return nil
}

func (r *Request) verifySignature(c CryptoSignatureVerificationMethod) error {
	data, err := r.SignatureData()
	if err != nil {
		return errors.Wrap(err, "signature data")
	}

	valid, err := c.Verify(data, r.SecureContainer.Signature)
	if err != nil {
		return errors.Wrap(err, "signature verification error")
	}

	if !valid {
		return errors.New("invalid signature")
	}

	return nil
}

// Container returns the request encrypted container content without the signature (which is also part of the encrypted
// container).
func (r *RequestSecureContainer) Container() (TLVContainer, error) {
	tlv, err := NewTLVContainer(nil)
	if err != nil {
		return nil, errors.Wrap(err, "tlv container")
	}

	tlv.SetBytes(TypeTimestamp.Uint16(), timestampEncode(r.Timestamp))

	clientDeviceUUID, err := clientDeviceUUIDEncode(r.ClientDeviceUUID)
	if err != nil {
		return nil, errors.Wrap(err, "client device uuid")
	}
	tlv.SetBytes(TypeClientDeviceUUID.Uint16(), clientDeviceUUID)

	tlv.SetByte(TypeFirewallProtocol.Uint16(), r.Protocol.ToBin())
	tlv.SetBytes(TypeFirewallPortStart.Uint16(), uint16Encode(r.PortStart))
	tlv.SetBytes(TypeFirewallPortEnd.Uint16(), uint16Encode(r.PortEnd))

	if r.ClientPublicIPv4 != nil {
		tlv.SetBytes(TypeClientPublicIPv4.Uint16(), ipAddressEncode(r.ClientPublicIPv4))
	}
	if r.ClientPublicIPv6 != nil {
		tlv.SetBytes(TypeClientPublicIPv6.Uint16(), ipAddressEncode(r.ClientPublicIPv6))
	}

	if r.ServerPublicIPv4 != nil {
		tlv.SetBytes(TypeServerPublicIPv4.Uint16(), ipAddressEncode(r.ServerPublicIPv4))
	}
	if r.ServerPublicIPv6 != nil {
		tlv.SetBytes(TypeServerPublicIPv6.Uint16(), ipAddressEncode(r.ServerPublicIPv6))
	}

	tlv.SetByte(TypeIPInfo.Uint16(), ipInfoEncode(r.IPInfo))
	tlv.SetBytes(TypeNonce.Uint16(), r.Nonce)

	tlv, err = tlv.Merge(r.AdditionalSecureData)
	if err != nil {
		return nil, errors.Wrap(err, "additional secure data merge")
	}

	tlv.SetBytes(TypeSignature.Uint16(), r.Signature)

	return tlv, nil
}

func RequestSecureContainerParse(c TLVContainer) (RequestSecureContainer, error) {
	r := RequestSecureContainer{}

	requestParseSubroutines := []requestParseSubroutine{
		requestParseSubroutineClientDeviceUUID,
		requestParseSubroutineTimestamp,
		requestParseSubroutineFirewallProtocol,
		requestParseSubroutineFirewallPortStart,
		requestParseSubroutineFirewallPortEnd,
		requestParseSubroutineClientPublicIP,
		requestParseSubroutineServerPublicIP,
		requestParseSubroutineIpInfo,
		requestParseSubroutineNonce,
		requestParseSubroutineSignature,
	}

	for _, f := range requestParseSubroutines {
		if err := f(&r, c); err != nil {
			return RequestSecureContainer{}, err
		}
	}

	r.AdditionalSecureData = c

	return r, nil
}

func RequestParse(b []byte, m CipherSuiteMux) (Request, error) {
	if m == nil {
		return Request{}, errors.New("CipherSuiteMux is nil")
	}

	if len(b) <= HeaderSize {
		return Request{}, ErrInvalidBytes
	}

	r := Request{}

	header, err := headerUnmarshal(b[:HeaderSize])
	if err != nil {
		return Request{}, errors.Wrap(err, "header unmarshal")
	}
	r.Header = header

	if !m.Supported(r.Header.CipherSuiteId) {
		return Request{}, ErrCipherSuiteNotSupported{r.Header.CipherSuiteId}
	}

	body, err := NewTLVContainer(b[HeaderSize:])
	if err != nil {
		return Request{}, errors.Wrap(err, "body tlv container parse")
	}

	additionalPlaintextData, exists := body.GetBytes(TypeContainer.Uint16())
	if exists {
		container, err := NewTLVContainer(additionalPlaintextData)
		if err != nil {
			return Request{}, errors.Wrap(err, "additional plaintext tlv container parse")
		}

		r.AdditionalPlaintextData = container
	}

	encryptedBody, exists := body.GetBytes(TypeEncryptedContainer.Uint16())
	if !exists {
		return Request{}, errors.Wrap(err, "no encrypted container in body")
	}

	cipherSuite := m.Get(r.Header.CipherSuiteId)
	if cipherSuite == nil {
		return Request{}, errors.New("returned cipher suite is empty")
	}

	decryptedContainerB, err := cipherSuite.Decrypt(encryptedBody)
	if err != nil {
		return Request{}, errors.Wrap(err, "decryption")
	}

	decryptedContainer, err := NewTLVContainer(decryptedContainerB)
	if err != nil {
		return Request{}, errors.Wrap(err, "encrypted tlv container")
	}

	r.SecureContainer, err = RequestSecureContainerParse(decryptedContainer)
	if err != nil {
		return Request{}, errors.Wrap(err, "request secure container parse")
	}

	if err := r.verifySignature(cipherSuite); err != nil {
		return Request{}, errors.Wrap(err, "signature verify")
	}

	return r, nil
}

type requestParseSubroutine func(r *RequestSecureContainer, container TLVContainer) error

func requestParseSubroutineClientDeviceUUID(r *RequestSecureContainer, container TLVContainer) error {
	if r == nil {
		return &ErrInvalidField{Field: "request secure container is nil"}
	}

	b, exists := container.GetBytes(TypeClientDeviceUUID.Uint16())
	if !exists {
		return &ErrMissingField{Field: "client device uuid"}
	}

	clientDeviceUUID, err := clientDeviceUUIDDecode(b)
	if err != nil {
		return errors.Wrap(err, "client device uuid decode")
	}

	r.ClientDeviceUUID = clientDeviceUUID

	container.Remove(TypeClientDeviceUUID.Uint16())
	return nil
}

func requestParseSubroutineTimestamp(r *RequestSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeTimestamp.Uint16())
	if !exists {
		return &ErrMissingField{Field: "timestamp"}
	}

	timestamp, err := timestampDecode(b)
	if err != nil {
		return errors.Wrap(err, "timestamp decode")
	}

	r.Timestamp = timestamp
	container.Remove(TypeTimestamp.Uint16())
	return nil
}

func requestParseSubroutineFirewallProtocol(r *RequestSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint8(container, TypeFirewallProtocol)
	if err != nil {
		return errors.Wrap(err, "firewall protocol")
	}

	r.Protocol = InternetProtocolNumber(i)
	container.Remove(TypeFirewallProtocol.Uint16())
	return nil
}

func requestParseSubroutineFirewallPortStart(r *RequestSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint16(container, TypeFirewallPortStart)
	if err != nil {
		return errors.Wrap(err, "firewall port start")
	}

	r.PortStart = i
	container.Remove(TypeFirewallPortStart.Uint16())
	return nil
}

func requestParseSubroutineFirewallPortEnd(r *RequestSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint16(container, TypeFirewallPortEnd)
	if err != nil {
		return errors.Wrap(err, "firewall port end")
	}

	r.PortEnd = i
	container.Remove(TypeFirewallPortEnd.Uint16())
	return nil
}

func requestParseSubroutineClientPublicIP(r *RequestSecureContainer, container TLVContainer) error {
	hasIp := false

	ip, err := requestParseSubroutineGenericIP(container, TypeClientPublicIPv4)
	if err == nil {
		r.ClientPublicIPv4 = ip
		hasIp = true
		container.Remove(TypeClientPublicIPv4.Uint16())
	}

	ip, err = requestParseSubroutineGenericIP(container, TypeClientPublicIPv6)
	if err == nil {
		r.ClientPublicIPv6 = ip
		hasIp = true
		container.Remove(TypeClientPublicIPv6.Uint16())
	}

	if !hasIp {
		return &ErrMissingField{Field: "client ipv4 or ipv6 address"}
	}

	return nil
}

func requestParseSubroutineServerPublicIP(r *RequestSecureContainer, container TLVContainer) error {
	hasIp := false

	ip, err := requestParseSubroutineGenericIP(container, TypeServerPublicIPv4)
	if err == nil {
		r.ServerPublicIPv4 = ip
		hasIp = true
		container.Remove(TypeServerPublicIPv4.Uint16())
	}

	ip, err = requestParseSubroutineGenericIP(container, TypeServerPublicIPv6)
	if err == nil {
		r.ServerPublicIPv6 = ip
		hasIp = true
		container.Remove(TypeServerPublicIPv6.Uint16())
	}

	if !hasIp {
		return &ErrMissingField{Field: "client ipv4 or ipv6 address"}
	}

	return nil
}

func requestParseSubroutineIpInfo(r *RequestSecureContainer, container TLVContainer) error {
	b, exists := container.GetByte(TypeIPInfo.Uint16())
	if !exists {
		return &ErrMissingField{Field: "ip info"}
	}

	r.IPInfo = ipInfoDecode(b)
	container.Remove(TypeIPInfo.Uint16())
	return nil
}

func requestParseSubroutineNonce(r *RequestSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeNonce.Uint16())
	if !exists {
		return &ErrMissingField{Field: "nonce"}
	}

	r.Nonce = b
	container.Remove(TypeNonce.Uint16())
	return nil
}

func requestParseSubroutineSignature(r *RequestSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeSignature.Uint16())
	if !exists {
		return &ErrMissingField{Field: "signature"}
	}

	r.Signature = b
	container.Remove(TypeSignature.Uint16())
	return nil
}

func requestParseSubroutineGenericIP(container TLVContainer, t TLVType) (net.IP, error) {
	b, exists := container.GetBytes(t.Uint16())
	if !exists {
		return nil, &ErrMissingField{}
	}

	if !(len(b) == 16 || len(b) == 4) {
		return nil, &ErrInvalidField{}
	}

	var ip net.IP = b
	return ip, nil
}

func requestParseSubroutineGenericUint8(container TLVContainer, t TLVType) (uint8, error) {
	b, exists := container.GetBytes(t.Uint16())
	if !exists {
		return 0, &ErrMissingField{}
	}

	i, err := uint8Decode(b)
	if err != nil {
		return 0, errors.Wrap(err, "uint8 decode")
	}

	return i, nil
}
func requestParseSubroutineGenericUint16(container TLVContainer, t TLVType) (uint16, error) {
	b, exists := container.GetBytes(t.Uint16())
	if !exists {
		return 0, &ErrMissingField{}
	}

	i, err := uint16Decode(b)
	if err != nil {
		return 0, errors.Wrap(err, "uint16 decode")
	}

	return i, nil
}
