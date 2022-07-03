package openspalib_old

import (
	"fmt"

	"github.com/pkg/errors"
)

var (
	ErrInvalidBytes = errors.New("invalid bytes")
	ErrInvalidInput = errors.New("invalid input")
)

type ErrMissingField struct {
	Field string
}

type ErrInvalidField struct {
	Field string
}

func (e *ErrMissingField) Error() string {
	if e.Field == "" {
		return "missing field"
	}

	return fmt.Sprintf("missing field: %s", e.Field)
}

func (e *ErrInvalidField) Error() string {
	if e.Field == "" {
		return "invalid field"
	}
	return fmt.Sprintf("invalid field: %s", e.Field)
}
