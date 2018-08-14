package server

import "fmt"

const VersionMajor = 0
const VersionMinor = 1
const VersionBugfix = 0

var Version = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionBugfix)
