package response

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/cryptography"
	"github.com/greenstatic/openspalib/header"
	"github.com/greenstatic/openspalib/tools"
	"time"
)

const (
	PacketPayloadSize = 24   // bytes
	MaxSize           = 1232 // bytes
	nonceSize         = 3    // bytes
	maxPort           = 65535
)

type packetPayload struct {
	Timestamp       time.Time
	Nonce           []byte
	Protocol        byte
	StartPort       uint16
	EndPort         uint16
	Duration        uint16
	SignatureMethod byte
}

type Packet struct {
	Header    header.Header
	Payload   packetPayload
	Signature []byte
	ByteData  []byte // header + payload encoded
	Encrypted []byte
}

type New struct {
	Protocol         byte
	StartPort        uint16
	EndPort          uint16
	Duration         uint16
	SignatureMethod  byte
	EncryptionMethod byte
}

// Creates a response packet struct and uses the fields of the New struct
// for the packet payload.
func (n *New) Create() (Packet, error) {

	// Check if we support the encryption method
	if !tools.ElementInSlice(n.EncryptionMethod, openspalib.SupportedEncryptionMethods()) {
		return Packet{}, errors.New("unsupported encryption method")
	}

	header := header.Header{
		openspalib.Version,
		false,
		n.EncryptionMethod,
	}

	// Check if we support the signature method
	if !tools.ElementInSlice(n.SignatureMethod, openspalib.SupportedSignatureMethods()) {
		return Packet{}, errors.New("unsupported signature method")
	}

	// Check that both start port and end port are present. Note this
	// check is a bit dumb since we compare if the port is larger than
	// maxPort even though StartPort/EndPort are uint16 - meaning they
	// can never be larger the maxPort.
	portCanBeZero := tools.PortCanBeZero(n.Protocol)
	if (!portCanBeZero && n.StartPort == 0) || n.StartPort > maxPort {
		return Packet{}, errors.New("unsupported start port")
	}

	if (!portCanBeZero && n.EndPort == 0) || n.EndPort > maxPort {
		return Packet{}, errors.New("unsupported end port")
	}

	if n.StartPort > n.EndPort {
		return Packet{}, errors.New("start port is larger than end port")
	}

	// Generate a random nonce
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)

	if err != nil {
		return Packet{}, errors.New("failed to generate random nonce")
	}

	// Take the current timestamp for the packet payload
	timestamp := time.Now()

	payload := packetPayload{
		timestamp,
		nonce,
		n.Protocol,
		n.StartPort,
		n.EndPort,
		n.Duration,
		n.SignatureMethod,
	}

	p := Packet{}
	p.Header = header
	p.Payload = payload

	return p, nil
}

// Decodes an encrypted OpenSPA response packet and returns a Packet struct.
// If we are unable to decode the packet we will return an error.
func Decode(data []byte, privKey *rsa.PrivateKey) (Packet, error) {

	p := Packet{}
	p.Encrypted = data

	head, err := header.Decode(data)
	if err != nil {
		return Packet{}, err
	}

	p.Header = head

	bodyEnc, err := removeHeader(data)
	if err != nil {
		return Packet{}, err
	}

	headBytes := data[:header.Size]

	body := make([]byte, 0)

	// Decrypt the packet
	switch head.EncryptionMethod {
	case openspalib.EncryptionMethod_RSA2048_AES256CBC:
		body, err = cryptography.DecryptWithRSA_2048_with_AES_256_CBC(bodyEnc, privKey)
		if err != nil {
			return Packet{}, err
		}
	}

	if len(body) < PacketPayloadSize {
		return Packet{}, errors.New("payload is smaller than the size defined by OpenSPA protocol")
	}

	payload, signature, err := decode(body)
	if err != nil {
		return Packet{}, err
	}

	bodyWithoutSignature := body[:PacketPayloadSize]

	bytesData := make([]byte, 0, len(headBytes)+len(body))
	bytesData = append(bytesData, headBytes...)
	bytesData = append(bytesData, bodyWithoutSignature...)

	p.ByteData = bytesData
	p.Payload = payload
	p.Signature = signature

	return p, nil
}

// Returns the encrypted byte content of the packet
func (p *Packet) Export() ([]byte, error) {
	// Check if the packet is signed
	if len(p.Signature) == 0 {
		return nil, errors.New("packet has not been signed yet")
	}

	// Check if the packet is encrypted
	if len(p.Encrypted) == 0 {
		return nil, errors.New("packet has not been encrypted yet")
	}

	// Concatenate the header and the encrypted payload to
	// form the final packet
	head, err := p.Header.Encode()
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 0, len(head)+len(p.Encrypted))
	packet = append(packet, head...)
	packet = append(packet, p.Encrypted...)

	return packet, nil
}
