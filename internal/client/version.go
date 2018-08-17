package client

import "fmt"

const VersionMajor = 0
const VersionMinor = 1
const VersionBugfix = 1

var Version = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionBugfix)
