package openspalib_old

import "testing"

func TestInternetProtocolNumberSupported(t *testing.T) {
	p := InternetProtocolNumberSupported()
	// There are 5 protocols we currently have implemented: ICMP, IPv4, TCP, UDP and ICMPv6
	if len(p) != 5 {
		t.Errorf("InternetProtocolNumberSupported has changed")
	}
}

func TestPortCanBeZero(t *testing.T) {
	tests := []struct {
		inputData      InternetProtocolNumber
		expectedResult bool
		onErrorStr     string
	}{
		{
			inputData:      ProtocolICMP,
			expectedResult: true,
			onErrorStr:     "ICMP should be allowed to have port zero",
		},
		{
			inputData:      ProtocolIPV4,
			expectedResult: true,
			onErrorStr:     "IPv4 should be allowed to have port zero",
		},
		{
			inputData:      ProtocolTCP,
			expectedResult: false,
			onErrorStr:     "TCP should not be allowed to have port zero",
		},
		{
			inputData:      ProtocolUDP,
			expectedResult: false,
			onErrorStr:     "UDP should not be allowed to have port zero",
		},
		{
			inputData:      ProtocolICMPv6,
			expectedResult: true,
			onErrorStr:     "ICMPv6 should be allowed to have port zero",
		},
	}

	for i, test := range tests {
		testNo := i + 1
		result := portCanBeZero(test.inputData)

		if test.expectedResult != result {
			t.Errorf("Test case: %d failed (%s), returned boolean does not match %v != %v",
				testNo, test.onErrorStr, test.expectedResult, result)
		}
	}
}
