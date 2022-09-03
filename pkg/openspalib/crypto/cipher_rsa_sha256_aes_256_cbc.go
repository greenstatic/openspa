package crypto

import (
	"crypto/rsa"

	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
)

var _ CipherSuite = &CipherSuite_RSA_SHA256_AES256CBC{}

//nolint:revive,stylecheck
type CipherSuite_RSA_SHA256_AES256CBC struct {
	resolver PublicKeyResolver

	dec *RSADecrypter
	sig *RSA_SHA256Signer
}

//nolint:revive,stylecheck,lll
func NewCipherSuite_RSA_SHA256_AES256CBC(privKey *rsa.PrivateKey, rs PublicKeyResolver) *CipherSuite_RSA_SHA256_AES256CBC {
	r := &CipherSuite_RSA_SHA256_AES256CBC{
		resolver: rs,
		dec:      NewRSADecrypter(privKey),
		sig:      NewRSA_SHA256Signer(privKey),
	}

	return r
}

func (r *CipherSuite_RSA_SHA256_AES256CBC) CipherSuiteID() CipherSuiteID {
	return CipherRSA_SHA256_AES256CBC_ID
}

// Secure
//  1. Uses sender's RSA private key + SHA-256 to sign the header+packet contents
//  2. Generates a session key
//  3. Uses session key to AES-256-CBC encrypt the packet and signature contents
//  4. Encrypts the session key using the receiver's RSA public key
//
// Returns a Container according to the Encrypted TLV definition
func (r *CipherSuite_RSA_SHA256_AES256CBC) Secure(header []byte, packet, meta tlv.Container) (tlv.Container, error) {
	receiverPubKey, err := r.resolver.PublicKey(packet, meta)
	if err != nil {
		return nil, errors.Wrap(err, "resolve receiver public key")
	}

	receiverRSAPubKey, ok := receiverPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("resolved receiver public key isn not a RSA public key")
	}

	enc := tlv.NewContainer()

	encPayload := tlv.NewContainer()
	packetB := packet.Bytes()
	encPayload.SetBytes(PacketKey, packetB)

	signature, err := r.sign(header, packetB)
	if err != nil {
		return nil, errors.Wrap(err, "signing")
	}

	encPayload.SetBytes(SignatureKey, signature)

	cipher, iv, key, err := AES256CBCEncrypt(encPayload.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "aes256cbc encryption")
	}

	enc.SetBytes(EncryptedPayloadKey, cipher)

	sessionKey := make([]byte, len(iv)+len(key))
	copy(sessionKey, iv)
	copy(sessionKey[len(iv):], key)

	sessionKeyEnc, err := NewRSAEncrypter(receiverRSAPubKey).Encrypt(sessionKey)
	if err != nil {
		return nil, errors.Wrap(err, "session key encrypt with rsa")
	}

	enc.SetBytes(EncryptedSessionKey, sessionKeyEnc)

	return enc, nil
}

func (r *CipherSuite_RSA_SHA256_AES256CBC) Unlock(header []byte, ec tlv.Container) (tlv.Container, error) {
	sessionKeyEnc, ok := ec.GetBytes(EncryptedSessionKey)
	if !ok {
		return nil, errors.New("get encrypted session")
	}

	encryptedPayload, ok := ec.GetBytes(EncryptedPayloadKey)
	if !ok {
		return nil, errors.New("get encrypted payload")
	}

	sessionKey, err := r.dec.Decrypt(sessionKeyEnc)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt session key")
	}

	if len(sessionKey) != 32+16 {
		return nil, errors.New("invalid session key length")
	}

	iv := sessionKey[:16]
	key := sessionKey[16:]

	payload, err := NewAES256CBCDecrypter(iv, key).Decrypt(encryptedPayload)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt payload")
	}

	payloadContainer, err := tlv.UnmarshalTLVContainer(payload)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal payload container")
	}

	packet, ok := payloadContainer.GetBytes(PacketKey)
	if !ok {
		return nil, errors.New("no packet")
	}

	packetContainer, err := tlv.UnmarshalTLVContainer(packet)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal packet container")
	}

	signature, ok := payloadContainer.GetBytes(SignatureKey)
	if !ok {
		return nil, errors.New("no signature")
	}

	sigPubKey, err := r.resolver.PublicKey(packetContainer, nil)
	if err != nil {
		return nil, errors.Wrap(err, "resolve sender's public key")
	}

	sigRSAPubKey, ok := sigPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("resolved non RSA sender's public key")
	}

	signatureContent := make([]byte, len(header)+len(packet))
	copy(signatureContent, header)
	copy(signatureContent[len(header):], packet)

	sigValid, err := NewRSA_SHA256SignatureVerifier(sigRSAPubKey).Verify(signatureContent, signature)
	if !sigValid || err != nil {
		if err != nil {
			return nil, errors.Wrap(err, "invalid signature")
		}
		return nil, errors.New("invalid signature")
	}

	return packetContainer, nil
}

func (r *CipherSuite_RSA_SHA256_AES256CBC) sign(header, body []byte) ([]byte, error) {
	content := make([]byte, len(header)+len(body))

	copy(content, header)
	copy(content[len(header):], body)

	return r.sig.Sign(content)
}
