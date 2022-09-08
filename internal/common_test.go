package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommandExecute_Stdout(t *testing.T) {
	exec := CommandExecute{}

	b, err := exec.Execute("echo", []byte{}, "one", "two", "three")
	assert.NoError(t, err)
	assert.Equal(t, "one two three\n", string(b))
}

func TestCommandExecute_Stdin(t *testing.T) {
	exec := CommandExecute{}

	b, err := exec.Execute("cat", []byte("one two three"))
	assert.NoError(t, err)
	assert.Equal(t, "one two three", string(b))
}
