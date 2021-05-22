package openspalib

import (
	"crypto/rsa"
	"net"
	"time"

	"github.com/pkg/errors"
)

const (
	RequestPacketBodySize = 68 // bytes
)

// Request represents an OpenSPA Request packet. Either create a Request struct using NewRequest() or craft it yourself.
// Then you need to call the Request function Sign().
type Request struct {
	Head Header
	Body RequestBody

	Signature []byte
}

// RequestBody represents the body of the OpenSPA request. It contains low level fields that should generally be filled
// by higher level functions, such as NewRequest().
type RequestBody struct {
	Timestamp       time.Time
	ClientDeviceID  string
	Nonce           Nonce
	Protocol        InternetProtocolNumber
	StartPort       uint16
	EndPort         uint16
	SignatureMethod SignatureMethod

	ClientBehindNat bool
	ClientPublicIP  net.IP
	ServerPublicIP  net.IP
}

// RequestData contains fields that will be used to generate a Request.
type RequestData struct {
	ClientDeviceID   string
	Protocol         InternetProtocolNumber
	StartPort        uint16
	EndPort          uint16
	ClientBehindNat  bool
	EncryptionMethod EncryptionMethod
	SignatureMethod  SignatureMethod

	ClientPublicIP net.IP
	ServerPublicIP net.IP
}

// NewRequest creates a Request struct
func NewRequest(data RequestData) (*Request, error) {
	r := Request{}
	r.Head = Header{}
	r.Body = RequestBody{}

	r.Head.Version = Version
	r.Head.IsRequest = true

	// Check if we support the encryption method
	if !EncryptionMethodIsSupported(data.EncryptionMethod) {
		return &Request{}, errors.New("unsupported encryption method")
	}
	r.Head.EncryptionMethod = data.EncryptionMethod

	// Check if we support the signature method
	if !SignatureMethodIsSupported(data.SignatureMethod) {
		return &Request{}, errors.New("unsupported signature method")
	}
	r.Body.SignatureMethod = data.SignatureMethod

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
		return &Request{}, errors.New("unsupported start port")
	}

	if (!portCanBeZero && data.EndPort == 0) || data.EndPort > maxTCPUDPPort {
		return &Request{}, errors.New("unsupported end port")
	}

	if data.StartPort > data.EndPort {
		return &Request{}, errors.New("start port is larger than end port")
	}

	r.Body.StartPort = data.StartPort
	r.Body.EndPort = data.EndPort
	r.Body.Protocol = data.Protocol

	// Check if the client public IP is present
	if len(data.ClientPublicIP) == 0 {
		return &Request{}, errors.New("client public ip is empty")
	}
	r.Body.ClientPublicIP = data.ClientPublicIP

	// Check if the servers public IP is present
	if len(data.ServerPublicIP) == 0 {
		return &Request{}, errors.New("server public ip is empty")
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

	return &r, nil
}

// SignAndEncrypt signs the request, encrypts the request and returns the final full packet
func (r *Request) SignAndEncrypt(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) ([]byte, error) {
	head, err := r.Head.Encode()
	if err != nil {
		return nil, err
	}

	if err := r.sign(privKey); err != nil {
		return nil, errors.Wrapf(err, "signature failure")
	}

	ciphertext, err := r.encrypt(pubKey)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 0, len(head)+len(ciphertext))
	packet = append(packet, head...)
	packet = append(packet, ciphertext...)

	return packet, nil
}

func (r *Request) sign(privKey *rsa.PrivateKey) error {
	data, err := r.signaturePlaintextData()
	if err != nil {
		return err
	}

	signature, err := r.signRsaSha256(data, privKey)
	if err != nil {
		return err
	}

	r.Signature = signature
	return nil
}

// Return a byte slice that represents the data (header + body) that needs to be signed.
func (r *Request) signaturePlaintextData() ([]byte, error) {
	// IDEA - would be better if we would improve this check, instead of checking a couple of struct fields for their
	// (invalid) default values.

	// Check if the header has been created
	if r.Head.Version == 0 {
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

	data := make([]byte, 0, len(header)+len(body))
	data = append(data, header...)
	data = append(data, body...)

	return data, nil
}

// Signs the packet using a RSA private key, by taking a SHA-256 digest of the packet signature data.
func (r *Request) signRsaSha256(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	if r.Body.SignatureMethod != SignatureMethod_RSA_SHA256 {
		return nil, errors.New("tried to add signature using RSA SHA-256 however the packet was created for a different signature method")
	}

	signature, err := rsaSha256Signature(data, privKey)
	if err != nil {
		return nil, err // failed to sign packet
	}

	return signature, nil
}

// Data (plaintext) that will/should be encrypted.
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

func (r *Request) encrypt(pubKey *rsa.PublicKey) ([]byte, error) {
	plaintext, err := r.encryptionPlaintextData()
	if err != nil {
		return nil, err
	}

	ciphertext, err := r.encryptRsa2048WithAes256Cbc(plaintext, pubKey)
	return ciphertext, err
}

// Encrypts the byte data using 2048 bit RSA with AES 256-bit CBC mode and adds it to the packet.
func (r *Request) encryptRsa2048WithAes256Cbc(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := encryptWithRSA2048WithAES256CBC(plaintext, pubKey)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Encode encodes the packet body according to the OpenSPA specification.
func (body *RequestBody) Encode() ([]byte, error) {
	// This is our packet payload
	bodyBuff := make([]byte, RequestPacketBodySize)

	offset := 0 // we initialize the offset to 0

	// Unix Timestamp - 64 bit = 8 bytes
	const timestampSize = 8 // bytes
	timestampBin := timestampEncode(body.Timestamp)

	for i := 0; i < timestampSize; i++ {
		bodyBuff[offset+i] = timestampBin[i]
	}

	offset += timestampSize

	// Client device ID - 128 bits = 16 bytes
	const clientDeviceIdSize = 16 // bytes
	clientDeviceId, err := clientDeviceIdEncode(body.ClientDeviceID)
	if err != nil {
		return nil, err
	}

	for i := 0; i < clientDeviceIdSize; i++ {
		bodyBuff[offset+i] = clientDeviceId[i]
	}

	offset += clientDeviceIdSize

	// Nonce - 24 bits = 3 bytes
	for i := 0; i < nonceSize; i++ {
		bodyBuff[offset+i] = body.Nonce[i]
	}

	offset += nonceSize

	// Protocol - 8 bits = 1 byte
	const protocolSize = 1 // byte
	bodyBuff[offset] = body.Protocol.ToBin()
	offset += protocolSize

	// Start Port - 16 bits = 2 bytes
	const startPortSize = 2 // bytes
	startPort := encodePort(body.StartPort)

	for i := 0; i < startPortSize; i++ {
		bodyBuff[offset+i] = startPort[i]
	}

	offset += startPortSize

	// End Port - 16 bits = 2 bytes
	const endPortSize = 2 // bytes
	endPort := encodePort(body.EndPort)

	for i := 0; i < startPortSize; i++ {
		bodyBuff[offset+i] = endPort[i]
	}

	offset += endPortSize

	// Signature method - 8 bits = 1 byte
	const signatureMethodSize = 1 // byte
	bodyBuff[offset] = body.SignatureMethod.ToBin()
	offset += signatureMethodSize

	// Misc Field - 8 bits = 1 byte
	// X0000000 <- misc field, where X is Client NAT field

	const miscFieldsSize = 1 // byte
	miscField := encodeMiscField(body.ClientBehindNat)
	bodyBuff[offset] = miscField
	offset += miscFieldsSize

	// Reserved - 16 bits = 2 bytes
	const reservedSize = 2 // bytes

	// set all values to 0
	for i := 0; i < reservedSize; i++ {
		bodyBuff[offset+i] = 0
	}

	offset += reservedSize

	// Client Public IP - 128 bits = 16 bytes - could be IPv4 or IPv6
	const clientPublicIPSize = 16 // bytes
	clientPublicIP, err := ipAddressToBinIP(body.ClientPublicIP)
	if err != nil {
		return nil, err
	}

	for i := 0; i < clientPublicIPSize; i++ {
		bodyBuff[offset+i] = clientPublicIP[i]
	}

	offset += clientPublicIPSize

	// Server Public IP - 128 bit = 16 bytes - could be IPv4 or IPv6
	const serverPublicIPSize = 16 //bytes
	serverPublicIP, err := ipAddressToBinIP(body.ServerPublicIP)
	if err != nil {
		return nil, err
	}

	for i := 0; i < serverPublicIPSize; i++ {
		bodyBuff[offset+i] = serverPublicIP[i]
	}

	offset += serverPublicIPSize

	if offset != RequestPacketBodySize {
		return nil, errors.New("encoded payload is not the correct size")
	}

	return bodyBuff, nil
}
