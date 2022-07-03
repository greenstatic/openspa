package openspalib_old

import (
	"bytes"
	"github.com/pkg/errors"
	"time"
)

type Response struct {
	Header Header

	// Body
	AdditionalPlaintextData TLVContainer
	SecureContainer         ResponseSecureContainer
}

type ResponseSecureContainer struct {
	Timestamp time.Time
	Nonce     []byte

	Protocol  InternetProtocolNumber
	PortStart uint16
	PortEnd   uint16

	Duration time.Duration

	AdditionalSecureData TLVContainer

	Signature []byte
}

type ResponseData struct {
	Protocol  InternetProtocolNumber
	PortStart uint16
	PortEnd   uint16

	Duration time.Duration

	AdditionalSecureData    TLVContainer
	AdditionalPlaintextData TLVContainer
}

func NewResponse(data ResponseData, transactionId uint8) Response {
	r := Response{}

	r.Header = Header{
		TransactionId: transactionId,
	}
	r.Header.SetVersion(Version)
	r.Header.SetType(PDUResponseType)
	r.AdditionalPlaintextData = data.AdditionalPlaintextData

	r.SecureContainer = ResponseSecureContainer{
		Timestamp:            time.Now(),
		Nonce:                randomByteSlice(nonceSize),
		Protocol:             data.Protocol,
		PortStart:            data.PortStart,
		PortEnd:              data.PortEnd,
		Duration:             data.Duration,
		AdditionalSecureData: data.AdditionalSecureData,
	}

	return r
}

func (r *Response) SignAndEncrypt(c CipherSuite) ([]byte, error) {
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
		return nil, errors.Wrap(err, "buuffer write")
	}

	return b.Bytes(), nil
}

func (r *Response) SignatureData() ([]byte, error) {
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

func (r *Response) sign(c CipherSuite) ([]byte, error) {
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

func (r *Response) verifySignature(c CryptoSignatureVerificationMethod) error {
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

func (r *Response) Validate() error {
	// TODO
	return nil
}

// Container returns the response encrypted container content without the signature (which is also part of the encrypted
// container).
func (r *ResponseSecureContainer) Container() (TLVContainer, error) {
	tlv, err := NewTLVContainer(nil)
	if err != nil {
		return nil, errors.Wrap(err, "tlv container")
	}

	tlv.SetBytes(TypeTimestamp.Uint16(), timestampEncode(r.Timestamp))
	tlv.SetBytes(TypeNonce.Uint16(), r.Nonce)

	tlv.SetByte(TypeFirewallProtocol.Uint16(), r.Protocol.ToBin())
	tlv.SetBytes(TypeFirewallPortStart.Uint16(), uint16Encode(r.PortStart))
	tlv.SetBytes(TypeFirewallPortEnd.Uint16(), uint16Encode(r.PortEnd))

	tlv.SetBytes(TypeDuration.Uint16(), uintVarEncode(r.Duration.Nanoseconds()))

	tlv, err = tlv.Merge(r.AdditionalSecureData)
	if err != nil {
		return nil, errors.Wrap(err, "additional secure data merge")
	}

	tlv.SetBytes(TypeSignature.Uint16(), r.Signature)

	return tlv, nil
}

func ResponseParse(b []byte, m CipherSuiteMux) (Response, error) {
	if m == nil {
		return Response{}, errors.New("CipherSuiteMux is nil")
	}

	if len(b) <= HeaderSize {
		return Response{}, ErrInvalidBytes
	}

	r := Response{}

	header, err := headerUnmarshal(b[:HeaderSize])
	if err != nil {
		return Response{}, errors.Wrap(err, "header unmarshal")
	}
	r.Header = header

	if !m.Supported(r.Header.CipherSuiteId) {
		return Response{}, ErrCipherSuiteNotSupported{r.Header.CipherSuiteId}
	}

	body, err := NewTLVContainer(b[HeaderSize:])
	if err != nil {
		return Response{}, errors.Wrap(err, "body tlv container parse")
	}

	additionalPlaintextData, exists := body.GetBytes(TypeContainer.Uint16())
	if exists {
		container, err := NewTLVContainer(additionalPlaintextData)
		if err != nil {
			return Response{}, errors.Wrap(err, "additional plaintext tlv container parse")
		}

		r.AdditionalPlaintextData = container
	}

	encryptedBody, exists := body.GetBytes(TypeEncryptedContainer.Uint16())
	if !exists {
		return Response{}, errors.Wrap(err, "no encrypted container in body")
	}

	cipherSuite := m.Get(r.Header.CipherSuiteId)
	if cipherSuite == nil {
		return Response{}, errors.New("returned cipher suite is empty")
	}

	decryptedContainerB, err := cipherSuite.Decrypt(encryptedBody)
	if err != nil {
		return Response{}, errors.Wrap(err, "decryption")
	}

	decryptedContainer, err := NewTLVContainer(decryptedContainerB)
	if err != nil {
		return Response{}, errors.Wrap(err, "encrypted tlv container")
	}

	r.SecureContainer, err = ResponseSecureContainerParse(decryptedContainer)
	if err != nil {
		return Response{}, errors.Wrap(err, "request secure container parse")
	}

	if err := r.verifySignature(cipherSuite); err != nil {
		return Response{}, errors.Wrap(err, "signature verify")
	}

	return r, nil
}

func ResponseSecureContainerParse(c TLVContainer) (ResponseSecureContainer, error) {
	r := ResponseSecureContainer{}

	responseParseSubroutines := []responseParseSubroutine{
		responseParseSubroutineTimestamp,
		responseParseSubroutineNonce,
		responseParseSubroutineFirewallProtocol,
		responseParseSubroutineFirewallPortStart,
		responseParseSubroutineFirewallPortEnd,
		responseParseSubroutineDuration,
		responseParseSubroutineSignature,
	}

	for _, f := range responseParseSubroutines {
		if err := f(&r, c); err != nil {
			return ResponseSecureContainer{}, err
		}
	}

	r.AdditionalSecureData = c

	return r, nil
}

type responseParseSubroutine func(r *ResponseSecureContainer, container TLVContainer) error

func responseParseSubroutineTimestamp(r *ResponseSecureContainer, container TLVContainer) error {
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

func responseParseSubroutineFirewallProtocol(r *ResponseSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint8(container, TypeFirewallProtocol)
	if err != nil {
		return errors.Wrap(err, "firewall protocol")
	}

	r.Protocol = InternetProtocolNumber(i)
	container.Remove(TypeFirewallProtocol.Uint16())
	return nil
}

func responseParseSubroutineFirewallPortStart(r *ResponseSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint16(container, TypeFirewallPortStart)
	if err != nil {
		return errors.Wrap(err, "firewall port start")
	}

	r.PortStart = i
	container.Remove(TypeFirewallPortStart.Uint16())
	return nil
}

func responseParseSubroutineFirewallPortEnd(r *ResponseSecureContainer, container TLVContainer) error {
	i, err := requestParseSubroutineGenericUint16(container, TypeFirewallPortEnd)
	if err != nil {
		return errors.Wrap(err, "firewall port end")
	}

	r.PortEnd = i
	container.Remove(TypeFirewallPortEnd.Uint16())
	return nil
}

func responseParseSubroutineNonce(r *ResponseSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeNonce.Uint16())
	if !exists {
		return &ErrMissingField{Field: "nonce"}
	}

	r.Nonce = b
	container.Remove(TypeNonce.Uint16())
	return nil
}

func responseParseSubroutineDuration(r *ResponseSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeDuration.Uint16())
	if !exists {
		return &ErrMissingField{Field: "duration"}
	}

	i, err := uintVarDecode(b)
	if err != nil {
		return errors.Wrap(err, "duration decode")
	}

	r.Duration = time.Duration(i)
	container.Remove(TypeDuration.Uint16())
	return nil
}

func responseParseSubroutineSignature(r *ResponseSecureContainer, container TLVContainer) error {
	b, exists := container.GetBytes(TypeSignature.Uint16())
	if !exists {
		return &ErrMissingField{Field: "signature"}
	}

	r.Signature = b
	container.Remove(TypeSignature.Uint16())
	return nil
}
