package scan

import (
	"path/filepath"
	"strings"
)

// Additional targets are defensive discovery from community code; their
// presence or size alone never establishes compromise.
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts
func extraToolchainPath(path string) bool {
	path = strings.ToLower(filepath.ToSlash(path))
	for _, suffix := range []string{"/npm/bin/npm-cli.js", "/yarn/lib/cli.js", "/corepack/dist/pnpm.js", "/pnpm/bin/pnpm.cjs"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return strings.Contains(path, "/.npm/_npx/") && strings.HasSuffix(path, "/pnpm.cjs") || strings.Contains(path, "/.local/share/claude/versions/")
}
func (s *Scanner) checkExtraToolchains() {
	dir := filepath.Join(s.HomeDir, ".local", "share", "claude", "versions")
	if !s.pathInScope(dir) {
		return
	}
	entries, err := s.readDir(dir)
	if err != nil {
		s.persistenceError(dir, err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			s.checkApplicationFile(filepath.Join(dir, e.Name()))
		}
	}
}
