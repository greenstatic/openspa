package genOspa

import (
	"math"
	"regexp"
	"strconv"
	"testing"
)

func TestGetUin16WithouZeroRegexString(t *testing.T) {
	r, _ := regexp.Compile(getUin16WithoutZeroRegexString())

	if r.MatchString(string(0)) {
		t.Errorf("Matched 0")
	}

	// Testing values 1 - (2^16-1)
	for i := 1; i < int(math.Pow(2, 16)); i++ {
		str := strconv.Itoa(i)
		if !r.MatchString(string(str)) {
			t.Errorf("Failed to match valid uint16 value: %d", i)
			return
		}
	}

	// Testing values 2^16 - 2^17
	for i := int(math.Pow(2, 16)); i <= int(math.Pow(2, 17)); i++ {
		str := strconv.Itoa(i)
		if r.MatchString(string(str)) {
			t.Errorf("Match invalid uint16 value: %d", i)
			return
		}
	}

}
