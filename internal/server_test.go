package internal

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyLookupDir_LookupPublicKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "testPublicKeyLookupDir")
	require.NoError(t, err)

	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	}()

	_, pub1, err := crypto.RSAKeypair(2048)
	require.NoError(t, err)

	_, pub2, err := crypto.RSAKeypair(2048)
	require.NoError(t, err)

	pub1Str, err := crypto.RSAEncodePublicKey(pub1)
	require.NoError(t, err)
	pub2Str, err := crypto.RSAEncodePublicKey(pub2)
	require.NoError(t, err)

	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "client1.key"), []byte(pub1Str), fs.ModePerm))
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, "client2.key"), []byte(pub2Str), fs.ModePerm))

	l := NewPublicKeyLookupDir(dir)

	pubKey, err := l.LookupPublicKey("client1")
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)

	pubKey2, err := l.LookupPublicKey("client2.key")
	assert.NoError(t, err)
	assert.NotNil(t, pubKey2)

	pubKey3, err := l.LookupPublicKey("client3.key")
	assert.Error(t, err)
	assert.Nil(t, pubKey3)

}

func TestPublicKeyLookupDir_clientFilenameMatch(t *testing.T) {
	p := PublicKeyLookupDir{}

	assert.True(t, p.clientFilenameMatch("client1", "client1"))
	assert.True(t, p.clientFilenameMatch("client1", "client1.key"))
	assert.True(t, p.clientFilenameMatch("client1", "client1.pub"))
	assert.True(t, p.clientFilenameMatch("client1", "client1.foo"))
	assert.False(t, p.clientFilenameMatch("client1", "client1.foo.key"))
	assert.False(t, p.clientFilenameMatch("client1", "client"))
	assert.False(t, p.clientFilenameMatch("client1", "client2"))
	assert.False(t, p.clientFilenameMatch("client1", ""))
	assert.False(t, p.clientFilenameMatch("client1", "client11"))
}

func TestPublicKeyResolveFromClientUUID_PublicKey(t *testing.T) {
	l := crypto.NewPublicKeyLookupMock()
	p := NewPublicKeyResolveFromClientUUID(l)

	uuid := "2542286f-7bba-4965-a57d-83bcdd744afb"

	c := tlv.NewContainer()
	assert.NoError(t, openspalib.ClientUUIDToContainer(c, uuid))

	_, pub, err := crypto.RSAKeypair(2048)
	require.NoError(t, err)

	l.On("LookupPublicKey", uuid).Return(pub, nil).Once()

	pub2, err := p.PublicKey(c)
	assert.NoError(t, err)
	assert.NotNil(t, pub2)

	assert.Equal(t, pub, pub2)

	l.AssertExpectations(t)
}
