package openspalib

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

// PDU Body (unencrypted) format:
// 0               |   1           |       2       |           3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Timestamp                           |
// +                                                               +
// |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
// +                                                               +
// |                        Client Device ID                       |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Nonce                  |    Protocol   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Start Port          |           End Port            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                        Client Public IP                       +
// |                                                               |
// +                                                               +
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                        Server Public IP                       +
// |                                                               |
// +                                                               +
// +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |    IP Info    |       Reserved        |   Signature Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Additional Body Data (optional)                |
// ...                                                           ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Signature                          |
// ...                                                           ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// ----------------------------------------------------------------------
// * Timestamp (8 bytes = 64 bits): UNIX 64 bit timestamp
// * Client Device ID (16 bytes): Client's device UUID ID
// * Protocol (1 byte): IANA Assigned Internet Protocol Numbers
//   see: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// * Start Port (2 bytes = 16 bits): Port range to allow, the start port
// * End Port (2 bytes = 16 bits): Port range to allow, the end port
// * Client Public IP (16 bytes = 128 bits): The client's public IPv4 or IPv6 address
// * Server Public IP (16 bytes = 128 bits): The server's public IPv4 or IPv6 address
// * Misc field (4 byte = 32 bits): Miscellaneous field
//   |NXXXXXXX|XXXXXXXX|XXXXXXSS|SSSSSSSS|
//   N - Client's behind NAT, boolean (1 bit)
//   X - Reserved for future use (21 bits)
//	 S - Signature offset (10 bits)
// * TLV NoEntries (variable field, but optional)
// * Signature field (variable length depending on signature algorithm)

const (
	RequestPacketBodySize = 68 // bytes, packet body size without the signature and TLV values
)

// Request represents an OpenSPA Request. Either create a Request struct using CraftRequest() or craft it yourself.
// Then you need to call the Request function Sign().
type Request struct {
	Head Header
	Body RequestBody

	Signature []byte
}

// RequestBody represents the body of the OpenSPA request. It contains low level fields that should generally be filled
// by higher level functions, such as CraftRequest(). RequestBody does not contain the signature, this is left for the
// Request struct.
type RequestBody struct {
	Timestamp       time.Time
	ClientDeviceID  string
	Nonce           Nonce

	Protocol        InternetProtocolNumber
	StartPort       uint16
	EndPort         uint16

	ClientPublicIP  net.IP
	ServerPublicIP  net.IP
	ClientBehindNat bool

	TlvValues []byte
}

// RequestData contains fields that will be used to generate a Request - i.e. higher level construct to generate
// lower level RequestBody struct.
type RequestData struct {
	ClientDeviceID  string

	Protocol        InternetProtocolNumber
	StartPort       uint16
	EndPort         uint16

	ClientPublicIP net.IP
	ServerPublicIP net.IP
	ClientBehindNat bool
}

// NewRequest creates a Request struct, signs it and then encrypting its. The returned byte slice is the raw byte
// representation of the final request and should be sent over the wire to the OpenSPA server to be processed.
func NewRequest(data RequestData, c CipherSuite) ([]byte, error) {
	r, err := CraftRequest(data, c.CipherSuiteId())
	if err != nil {
		return nil, errors.Wrap(err, "craft request")
	}

	b, err := r.SignAndEncrypt(c)
	if err != nil {
		return nil, errors.Wrap(err, "signing and encrypting")
	}

	return b, nil
}

// CraftRequest creates a Request struct without signing and encrypting it.
func CraftRequest(data RequestData, cipherId CipherSuiteId) (*Request, error) {
	r := Request{}
	r.Head = Header{}
	r.Body = RequestBody{}

	r.Head.SetVersion(Version)
	r.Head.SetType(PDURequestType)

	// Check if we support the cipher suite
	if !CipherSuiteIsSupported(cipherId) {
		return &Request{}, ErrCipherSuiteNotSupported{cipherId}
	}
	r.Head.CipherSuite = cipherId

	// Check if client device ID is valid
	_, err := clientDeviceIdEncode(data.ClientDeviceID)
	if err != nil {
		return &Request{}, errors.New("client device ID is not a UUID")
	}
	r.Body.ClientDeviceID = data.ClientDeviceID

	// Check that both start port and end port are present. Note this
	// check is a bit dumb since we compare if the port is larger than
	// maxPort even though StartPort/EndPort are uint16 - meaning they
	// can never be larger the maxPort.
	portCanBeZero := portCanBeZero(data.Protocol)
	if (!portCanBeZero && data.StartPort == 0) || data.StartPort > maxTCPUDPPort {
		return &Request{}, ErrUnsupportedStartPort
	}

	if (!portCanBeZero && data.EndPort == 0) || data.EndPort > maxTCPUDPPort {
		return &Request{}, ErrUnsupportedEndPort
	}

	if data.StartPort > data.EndPort {
		return &Request{}, ErrStartEndPortMismatch
	}

	r.Body.StartPort = data.StartPort
	r.Body.EndPort = data.EndPort
	r.Body.Protocol = data.Protocol

	// Check if the client public IP is present
	if len(data.ClientPublicIP) == 0 {
		return &Request{}, ErrClientIpIsEmpty
	}
	r.Body.ClientPublicIP = data.ClientPublicIP

	// Check if the servers public IP is present
	if len(data.ServerPublicIP) == 0 {
		return &Request{}, ErrServerIpIsEmpty
	}
	r.Body.ServerPublicIP = data.ServerPublicIP

	// Generate a random nonce
	nonce, err := RandomNonce()
	if err != nil {
		return &Request{}, err
	}
	r.Body.Nonce = nonce

	// Take the current timestamp for the packet payload
	r.Body.Timestamp = time.Now()

	r.Body.ClientBehindNat = data.ClientBehindNat

	return &r, nil
}

// SignAndEncrypt signs the request, encrypts the request and returns the final full packet represented in binary as
// a byte slice.
func (r *Request) SignAndEncrypt(c CipherSuite) ([]byte, error) {
	head, err := r.Head.Encode()
	if err != nil {
		return nil, err
	}

	signature, err := r.sign(c)
	if err != nil {
		return nil, errors.Wrap(err, "signature failure")
	}

	r.Signature = signature

	ciphertext, err := r.encrypt(c)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 0, len(head)+len(ciphertext))
	packet = append(packet, head...)
	packet = append(packet, ciphertext...)

	return packet, nil
}

// sign uses a CryptoSignatureMethod to sign the request plaintext data and returns the signature as a byte slice.
func (r *Request) sign(c CryptoSignatureMethod) ([]byte, error) {
	data, err := r.signaturePlaintextData()
	if err != nil {
		return nil, errors.Wrap(err, "signature plaintext data")
	}

	signature, err := c.Sign(data)
	if err != nil {
		return nil, errors.Wrap(err, "signing")
	}

	return signature, nil
}

// Return a byte slice that represents the data (header + body) that needs to be signed.
func (r *Request) signaturePlaintextData() ([]byte, error) {
	// IDEA - would be better if we would improve this check, instead of checking a couple of struct fields for their
	// (invalid) default values.

	// Check if the header has been created
	if r.Head.Version() == 0 {
		return nil, errors.New("header has not been created for the packet yet")
	}

	// Check if the packet payload has been created
	if r.Body.ClientDeviceID == "" {
		return nil, errors.New("packet payload has not been created for the packet yet")
	}

	header, err := r.Head.Encode()
	if err != nil {
		return nil, err
	}

	body, err := r.Body.Encode()
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(header)+len(body)+len(r.Signature))
	data = append(data, header...)
	data = append(data, body...)
	data = append(data, r.Signature...)

	return data, nil
}

// encryptionPlaintextData returns the plaintext data that needs be encrypted.
func (r *Request) encryptionPlaintextData() ([]byte, error) {
	// Check if the packet payload has been created
	if r.Body.ClientDeviceID == "" {
		return nil, errors.New("packet payload has not been created for the packet yet")
	}

	if len(r.Signature) <= 0 {
		return nil, errors.New("request has not been signed yet")
	}

	body, err := r.Body.Encode()
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(body)+len(r.Signature))
	data = append(data, body...)
	data = append(data, r.Signature...)

	return data, nil
}

// encrypt uses a CryptoEncryptionMethod to encrypt the request plaintext data and returns the encrypted data as a byte
// slice.
func (r *Request) encrypt(c CryptoEncryptionMethod) ([]byte, error) {
	plaintext, err := r.encryptionPlaintextData()
	if err != nil {
		return nil, errors.Wrap(err, "encryption plaintext data")
	}

	ciphertext, err := c.Encrypt(plaintext)
	return ciphertext, errors.Wrap(err, "encrypting")
}


// Encode encodes the packet body according to the OpenSPA specification.
func (body *RequestBody) Encode() ([]byte, error) {
	return requestBodyMarshal(*body)
}

func (body *RequestBody) signatureOffset() uint {
	t := body.TlvValues
	if t == nil {
		return 0
	}
	return uint(len(t))
}

const (
	timestampFieldSize = 8 // Unix Timestamp - 64 bit = 8 bytes
	clientDeviceIdFieldSize = 16 // Client Device ID - 128 bits = 16 bytes
	protocolFieldSize = 1 // Protocol - 8 bits = 1 byte
	startPortFieldSize = 2 // Start Port - 16 bits = 2 bytes
	endPortFieldSize = 2 // End Port - 16 bits = 2 bytes
	clientPublicIPFieldSize = 16 // Client Public IP - 128 bits = 16 bytes - could be IPv4 or IPv6
	serverPublicIPFieldSize = 16 // Server Public IP - 128 bit = 16 bytes - could be IPv4 or IPv6
	miscFieldsFieldSize = 4 // Misc Field - 32 bits = 4 byte
	signatureOffsetBitSize = 10
)

func requestBodyMarshal(body RequestBody) ([]byte, error) {
	// This is our packet payload
	buffer := make([]byte, RequestPacketBodySize)

	offset := 0 // we initialize the offset to 0

	// Unix Timestamp
	timestampBin := timestampEncode(body.Timestamp)
	for i := 0; i < timestampFieldSize; i++ {
		buffer[offset+i] = timestampBin[i]
	}
	offset += timestampFieldSize

	// Client Device ID
	clientDeviceId, err := clientDeviceIdEncode(body.ClientDeviceID)
	if err != nil {
		return nil, errors.Wrap(err, "client device id encoding")
	}
	for i := 0; i < clientDeviceIdFieldSize; i++ {
		buffer[offset+i] = clientDeviceId[i]
	}
	offset += clientDeviceIdFieldSize

	// Nonce - 24 bits = 3 bytes
	for i := 0; i < nonceSize; i++ {
		buffer[offset+i] = body.Nonce[i]
	}
	offset += nonceSize

	// Protocol
	buffer[offset] = body.Protocol.ToBin()
	offset += protocolFieldSize

	// Start Port
	startPort := encodePort(body.StartPort)

	for i := 0; i < startPortFieldSize; i++ {
		buffer[offset+i] = startPort[i]
	}
	offset += startPortFieldSize

	// End Port
	endPort := encodePort(body.EndPort)
	for i := 0; i < endPortFieldSize; i++ {
		buffer[offset+i] = endPort[i]
	}
	offset += endPortFieldSize

	// Client Public IP
	clientPublicIP, err := ipAddressToBinIP(body.ClientPublicIP)
	if err != nil {
		return nil, errors.Wrap(err, "client public ip to bin")
	}
	for i := 0; i < clientPublicIPFieldSize; i++ {
		buffer[offset+i] = clientPublicIP[i]
	}
	offset += clientPublicIPFieldSize

	// Server Public IP
	serverPublicIP, err := ipAddressToBinIP(body.ServerPublicIP)
	if err != nil {
		return nil, err
	}
	for i := 0; i < serverPublicIPFieldSize; i++ {
		buffer[offset+i] = serverPublicIP[i]
	}
	offset += serverPublicIPFieldSize


	// Misc Field - 32 bits = 4 byte
	signatureOffset := body.signatureOffset()
	miscField, err := encodeMiscField(body.ClientBehindNat, signatureOffset)
	if err != nil {
		return nil, errors.Wrap(err, "encoding misc field")
	}

	if len(miscField) != miscFieldsFieldSize {
		return nil, fmt.Errorf("misc field size mismatch, expected %d bytes received %d bytes", miscField, miscFieldsFieldSize)
	}

	buffer[offset] = miscField[0]
	buffer[offset+1] = miscField[1]
	buffer[offset+2] = miscField[2]
	buffer[offset+3] = miscField[3]
	offset += miscFieldsFieldSize

	if signatureOffset > 0 {
		buffer = append(buffer, body.TlvValues...)
	}

	return buffer, nil
}
