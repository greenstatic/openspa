package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSAEncryptor_Encrypt(t *testing.T) {
	_, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	r := NewRSAEncrypter(pub)

	plaintext := []byte("Hello world!")

	cipher, err := r.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.NotNil(t, cipher)
	assert.NotEmpty(t, cipher)
	assert.Greater(t, len(cipher), len(plaintext))
	assert.Len(t, cipher, 2048/8)
}

func TestRSAEncryptor_Decrypt(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	re := NewRSAEncrypter(pub)
	rd := NewRSADecrypter(priv)

	plaintext := []byte("Hello world!")

	cipher, err := re.Encrypt(plaintext)
	require.NoError(t, err)

	plain, err := rd.Decrypt(cipher)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, plain)
}

func TestRSAEncryptor_Decrypt2(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	re := NewRSAEncrypter(pub)
	rd := NewRSADecrypter(priv)

	plaintext := []byte("Hello world!")

	cipher, err := re.Encrypt(plaintext)
	require.NoError(t, err)

	plain, err := rd.Decrypt(cipher)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, plain)
}

func TestRSA_SHA256Signor(t *testing.T) {
	priv, _, err := RSAKeypair(2048)
	assert.NoError(t, err)
	s := NewRSA_SHA256Signer(priv)

	plaintext := []byte("Hello world!")
	signature, err := s.Sign(plaintext)
	assert.NoError(t, err)

	assert.NotNil(t, signature)
	assert.NotEmpty(t, signature)
	assert.Greater(t, len(signature), len(plaintext))
	assert.Len(t, signature, 2048/8)
}

func TestRSA_SHA256SignatureVerifier(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	rs := NewRSA_SHA256Signer(priv)
	rv := NewRSA_SHA256SignatureVerifier(pub)

	plaintext := []byte("Hello world!")
	signature, err := rs.Sign(plaintext)
	require.NoError(t, err)

	ok, err := rv.Verify(plaintext, signature)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestRSA_SHA256SignatureVerifier_FalseSignature(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	rs := NewRSA_SHA256Signer(priv)
	rv := NewRSA_SHA256SignatureVerifier(pub)

	plaintext := []byte("Hello world!")
	signature, err := rs.Sign(plaintext)
	require.NoError(t, err)

	ok, err := rv.Verify(plaintext, append(signature, 0x00))
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestRSA_SHA256SignatureVerifier_DifferentPlaintext(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)
	rs := NewRSA_SHA256Signer(priv)
	rv := NewRSA_SHA256SignatureVerifier(pub)

	plaintext := []byte("Hello world!")
	signature, err := rs.Sign(plaintext)
	require.NoError(t, err)

	ok, err := rv.Verify(plaintext[:len(plaintext)-1], signature)
	assert.Error(t, err)
	assert.False(t, ok)
}

func TestRSAEncodeDecode(t *testing.T) {
	priv, pub, err := RSAKeypair(2048)
	assert.NoError(t, err)

	privEnc, err := RSAEncodePrivateKey(priv)
	assert.NoError(t, err)

	privDec, err := RSADecodePrivateKey(privEnc)
	assert.NoError(t, err)
	require.NotNil(t, privDec)

	assert.True(t, privDec.Equal(priv))

	pubEnc, err := RSAEncodePublicKey(pub)
	assert.NoError(t, err)
	pubDec, err := RSADecodePublicKey(pubEnc)
	assert.NoError(t, err)
	require.NotNil(t, pubDec)

	assert.True(t, pubDec.Equal(pub))
}
