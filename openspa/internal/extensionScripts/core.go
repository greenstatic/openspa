package extensionScripts

import (
	"os"
	"path/filepath"
)

type Scripts struct {
	UserDirectoryService string
	Authorization        string
	RuleAdd              string
	RuleRemove           string
}

func (script *Scripts) GetUserDirectoryService() *userDirectoryService {
	rootDir, path := resolvePath(script.UserDirectoryService)
	return &userDirectoryService{rootDir, path}
}

func (script *Scripts) GetAuthorization() *authorization {
	rootDir, path := resolvePath(script.Authorization)
	return &authorization{rootDir, path}
}

func (script *Scripts) GetRuleAdd() *ruleAdd {
	rootDir, path := resolvePath(script.RuleAdd)
	return &ruleAdd{rootDir, path}
}

func (script *Scripts) GetRuleRemove() *ruleRemove {
	rootDir, path := resolvePath(script.RuleRemove)
	return &ruleRemove{rootDir, path}
}

// Returns the command's directory and path. The command can be
// absolute or relative.
func resolvePath(cmd string) (dir, path string) {
	// If the path is absolute, things are easy
	if filepath.IsAbs(cmd) {
		return filepath.Dir(cmd), cmd
	}

	// If path is local, it's a bit more work
	rootDir, err := os.Executable() // path of the server!
	if err != nil {
		panic(err)
	}
	rootDir = filepath.Dir(rootDir)                     // remove the actual executable
	rootDir = filepath.Join(rootDir, filepath.Dir(cmd)) // absolute path of the command
	cmdPath := filepath.Join(rootDir, filepath.Base(cmd))
	return rootDir, cmdPath
}
