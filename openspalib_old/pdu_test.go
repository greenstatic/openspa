package openspalib_old

import (
	"testing"
)

func TestErrCipherSuiteNotSupported(t *testing.T) {
	tests := []struct {
		inputData   CipherSuiteId
		expectedErr string
	}{
		// Test case: 1
		{
			inputData:   CipherSuiteId(0),
			expectedErr: "cipher suite 0 not supported",
		},
		// Test case: 2
		{
			inputData:   CipherSuiteId(1),
			expectedErr: "cipher suite 1 not supported",
		},
		// Test case: 3
		{
			inputData:   CipherSuiteId(123),
			expectedErr: "cipher suite 123 not supported",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		err := ErrCipherSuiteNotSupported{test.inputData}
		if test.expectedErr != err.Error() {
			t.Errorf("Test case: %d failed, error message did not match: %s != %s",
				testNo, test.expectedErr, err.Error())
		}
	}
}
