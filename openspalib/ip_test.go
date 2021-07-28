package openspalib

import (
	"net"
	"testing"
)

func TestPublicIPv4ResolverParseResponse(t *testing.T) {
	tests := []struct{
		input string
		ip net.IP
		err error
	}{
		// Test case: 1
		{
			input: `{"ip": "123.1.2.3"}`,
			ip: net.IP{123, 1, 2, 3},
			err: nil,
		},
		// Test case: 2
		{
			input: `{"foo": 3, "ip": "123.1.2.3", "bar":1.32}`,
			ip: net.IP{123, 1, 2, 3},
			err: nil,
		},
		// Test case: 3
		{
			input: `{"foo": 3, "ipv4": "123.1.2.3", "bar":1.32}`,
			ip: net.IP{123, 1, 2, 3},
			err: nil,
		},
		// Test case: 4
		{
			input: `{"foo": 3, "IP": "123.1.2.3", "bar":1.32}`,
			ip: net.IP{123, 1, 2, 3},
			err: nil,
		},
		// Test case: 5
		{
			input: `{"foo": 3, "internetAddress": "123.1.2.3", "bar":1.32}`,
			ip: nil,
			err: ErrMissingIPFieldResp,
		},
		// Test case: 6
		{
			input: `{"foo": 3, "IP": "300.1.2.3", "bar":1.32}`,
			ip: nil,
			err: ErrMissingIPFieldResp,
		},
	}

	for i, test := range tests {
		testNo := i + 1

		ip, err := publicIPv4ResolverParseResponse([]byte(test.input))

		if test.err != err {
			t.Errorf("Test case: %d failed, error: %v != %v", testNo, test.err, err)
		}

		if !test.ip.Equal(ip) {
			t.Errorf("Test case: %d failed, ip %s != %s", testNo, test.ip.String(), ip.String())
		}

	}
}