package response

import (
	"crypto/rsa"
	"errors"
	"github.com/greenstatic/openspalib"
	"github.com/greenstatic/openspalib/cryptography"
)

// Returns the signature data to sign (header+payload).
func (p *Packet) SignatureData() ([]byte, error) {

	// IDEA - would be better if we would improve this check, instead of
	// checking a couple of struct fields for their (invalid) default values.

	// Check if the header has been created
	if p.Header.Version == 0 {
		return nil, errors.New("header has not been created for the packet yet")
	}

	// Check if the packet payload has been created
	if p.Payload.TimestampToString() == "0" {
		return nil, errors.New("packet payload has not been created for the packet yet")
	}

	hByte, err := p.Header.Encode()
	if err != nil {
		return nil, err
	}

	pByte, err := p.Payload.Encode()

	p.ByteData = make([]byte, 0, len(hByte)+len(pByte))

	p.ByteData = append(p.ByteData, hByte...)
	p.ByteData = append(p.ByteData, pByte...)

	return p.ByteData, nil
}

// Returns an error if we are not allowed to sign the packet,
// in case we are allowed return nil.
func (p *Packet) canSign() error {
	if len(p.Signature) != 0 {
		return errors.New("packet already signed, please create a new packet")
	}

	if len(p.ByteData) == 0 {
		return errors.New("packet does not contain any byte data to append the signature")
	}

	return nil
}

// Adds to a packet the callers packet signature
func (p *Packet) AddSignature(signature []byte) error {

	// Are we allowed to sign the packet?
	if err := p.canSign(); err != nil {
		return err
	}

	p.Signature = signature

	return nil
}

// Signs the packet using a RSA private key, by taking a SHA-256 digest of the packet
// signature data.
func (p *Packet) Sign_RSA_SHA256(privKey *rsa.PrivateKey) error {

	// Are we allowed to sign the packet?
	if err := p.canSign(); err != nil {
		return err
	}

	if p.Payload.SignatureMethod != openspalib.SignatureMethod_RSA_SHA256 {
		return errors.New("tried to add signature using RSA SHA-256 however the packet was created for a different signature method")
	}

	signature, err := cryptography.RSA_SHA256_signature(p.ByteData, privKey)
	if err != nil {
		return err // failed to sign packet
	}

	p.AddSignature(signature)
	return nil
}
