package internal

import "fmt"

const VersionMajor = 0
const VersionMinor = 0
const VersionBugfix = 1
const VersionInfo = "dev"

func Version() string {
	base := fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionBugfix)
	if VersionInfo != "" {
		base += "-" + VersionInfo
	}

	return base
}
