package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLabelsToMap(t *testing.T) {
	l := map[string]string{"foo": "bar", "state": "zoo"}

	lbl := Labels(l)
	assert.Equal(t, l, lbl.ToMap())
}

func TestLabelsAdd_ShouldNotModifyPrevious(t *testing.T) {
	l := NewLabels()

	l1 := l.Add("foo", "bar")
	l2 := l1.Add("state", "zoo")

	require.Len(t, l1.ToMap(), 1)
	assert.Equal(t, "bar", l1.ToMap()["foo"])

	require.Len(t, l2.ToMap(), 2)
	assert.Equal(t, "bar", l2.ToMap()["foo"])
	assert.Equal(t, "zoo", l2.ToMap()["state"])
}
