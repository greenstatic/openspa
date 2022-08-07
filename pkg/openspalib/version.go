package openspalib

import "fmt"

const VersionMajor = 2
const VersionMinor = 0

func Version() string {
	return fmt.Sprintf("%d.%d", VersionMajor, VersionMinor)
}
