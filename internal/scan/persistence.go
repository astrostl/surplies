package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// checkApplicationPersistence inspects only documented entrypoints and their
// siblings. It does not walk entire application bundles or execute any tool.
func (s *Scanner) checkApplicationPersistence() {
	s.checkApplicationPatterns(ApplicationEntrypointGlobs(s.HomeDir, runtime.GOOS, os.Getenv))
}

func (s *Scanner) checkApplicationPatterns(patterns []string) {
	for _, pattern := range patterns {
		// Expand the directory, not the file: sidecars survive removal of the
		// entrypoint, and must still be reported in that case.
		dirs := s.persistenceDirs(filepath.Dir(pattern))
		for _, dir := range dirs {
			if !s.pathInScope(dir) {
				continue
			}
			s.checkPersistenceSiblings(dir)
			s.checkApplicationFile(filepath.Join(dir, filepath.Base(pattern)))
		}
	}
}

// filepath.Glob silently swallows permission errors. Expand the small set of
// installation globs explicitly so an unreadable installation is not clean.
func (s *Scanner) persistenceDirs(pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}
	}
	var matches []string
	for _, parent := range s.persistenceDirs(filepath.Dir(pattern)) {
		entries, err := s.readDir(parent)
		if err != nil {
			s.persistenceError(parent, err)
			continue
		}
		for _, entry := range entries {
			if ok, _ := filepath.Match(filepath.Base(pattern), entry.Name()); ok {
				path := filepath.Join(parent, entry.Name())
				info, err := os.Stat(path) // follow installation-directory symlinks
				if err != nil {
					s.persistenceError(path, err)
					continue
				}
				if info.IsDir() {
					matches = append(matches, path)
				}
			}
		}
	}
	return matches
}

func (s *Scanner) markPersistenceChecked(path string) bool {
	if s.persistenceChecked == nil {
		s.persistenceChecked = make(map[string]bool)
	}
	if s.persistenceChecked[path] {
		return false
	}
	s.persistenceChecked[path] = true
	return true
}

func (s *Scanner) persistenceError(path string, err error) {
	if os.IsNotExist(err) {
		return // an application or optional entrypoint is not installed
	}
	s.scanError(path, err)
}

func (s *Scanner) checkPersistenceSiblings(dir string) {
	if !s.markPersistenceChecked(dir) {
		return
	}
	entries, err := s.readDir(dir)
	if err != nil {
		s.persistenceError(dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !isPersistenceSidecar(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if s.markPersistenceChecked(path) {
			s.checkRepoArtifactName(path, e.Name())
		}
	}
}

func isPersistenceSidecar(name string) bool {
	return strings.HasSuffix(name, ".inz.cjs") || strings.HasSuffix(name, ".inz.orig")
}

func persistenceSignature(data []byte) (PayloadSignature, bool) {
	if sig, ok := payloadSignature(data); ok {
		return sig, true
	}
	// In documented entrypoints a sidecar reference is evidence even if the
	// module it points to has since been removed. Do not flag every require().
	for _, suffix := range []string{".inz.cjs", ".inz.orig"} {
		if strings.Contains(string(data), suffix) {
			return PayloadSignature{Signature: suffix, Desc: "entrypoint references a PolinRider injection sidecar", Attack: "polinrider (DPRK)"}, true
		}
	}
	return PayloadSignature{}, false
}

func (s *Scanner) checkApplicationFile(path string) {
	if !s.markPersistenceChecked(path) {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		s.persistenceError(path, err)
		return
	}
	if !info.Mode().IsRegular() {
		s.persistenceError(path, fmt.Errorf("expected a regular entrypoint file"))
		return
	}
	if s.processFile(path, ReadTimeout, func(local *Scanner, data []byte) {
		if sig, ok := persistenceSignature(normalizeASCII(data)); ok {
			local.addFinding(Finding{Check: "patched-application", Severity: SevCritical, Path: path,
				Detail: fmt.Sprintf("%s (attack: %s)", sig.Desc, sig.Attack)})
		} else {
			local.inspectGeneralContent(path, data)
		}
	}) != nil {
		s.stats.FilesChecked++
	}

}

// These paths can have legitimate uses. Report them as context for an
// investigation, not as proof that a RAT executed.
func (s *Scanner) checkRuntimeStaging() {
	paths := []string{filepath.Join(s.HomeDir, ".node_modules", "node_modules")}
	temps := []string{os.TempDir()}
	if runtime.GOOS != "windows" {
		temps = append(temps, "/tmp", "/var/tmp")
	}
	for _, dir := range temps {
		for _, name := range NullReceiverStagingNames {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	s.checkStagingPaths(paths)
}

func (s *Scanner) checkStagingPaths(paths []string) {
	seen := make(map[string]bool)
	for _, path := range paths {
		if seen[path] || !s.pathInScope(path) {
			continue
		}
		seen[path] = true
		if _, err := os.Stat(path); err == nil {
			s.addFinding(Finding{Check: "runtime-staging-artifact", Severity: SevWarn, Path: path,
				Detail: "Path documented in NullReceiver runtime/staging activity; legitimate uses are possible, correlate with payload or persistence findings (attack: polinrider (DPRK))"})
		} else if !os.IsNotExist(err) {
			s.scanError(path, err)
		}
	}
}

// scanError reports incomplete coverage; it never classifies the path as malware.
func (s *Scanner) scanError(path string, err error) {
	category := "other errors"
	if errors.Is(err, errFileTooLarge) {
		category = "size limit exceeded"
	}
	if os.IsPermission(err) {
		category = "permission denied"
	}
	if materializationRefused(err) {
		s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: path, coverageCategory: "not downloaded",
			Detail: "This path is a cloud-sync placeholder that macOS would not download (resource deadlock avoided), so its contents were not scanned. " +
				"Make it available offline and re-run to cover it."})
		return
	}
	s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: path,
		Detail: fmt.Sprintf("Could not fully inspect this path: %v", err), coverageCategory: category})
}

// Recursive discovery uses published sidecars and entrypoint shapes, without
// depending on product directory names. Roots select coverage, not new IOCs.
// https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/scan_macos.sh
// https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
func DefaultPersistenceRoots() []string {
	return persistenceRootsForOS(runtime.GOOS, os.Getenv)
}

func persistenceRootsForOS(goos string, getenv func(string) string) []string {
	var roots []string // Home discovery shares the project walk.
	if goos == "windows" {
		for _, key := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
			if root := getenv(key); root != "" {
				roots = append(roots, root)
			}
		}
	} else {
		if goos == "darwin" {
			roots = append(roots, "/Applications")
		}
		roots = append(roots, "/usr/local/lib", "/opt", "/usr/lib", "/usr/share")
	}
	return roots
}

// existingPersistenceRoots is the subset checkPersistenceRoots will actually
// walk, so the run header promises only coverage the scan delivers.
func existingPersistenceRoots() []string {
	var present []string
	for _, root := range DefaultPersistenceRoots() {
		if _, err := os.Stat(root); err == nil {
			present = append(present, root)
		}
	}
	return present
}

func (s *Scanner) checkPersistenceRoots() {
	for _, root := range DefaultPersistenceRoots() {
		if !s.pathInScope(root) {
			continue
		}
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		s.walkPersistenceRoot(root)
	}
}

func (s *Scanner) walkPersistenceRoot(root string) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		s.scanError(root, err)
		return
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		s.scanError(root, err)
		return
	}
	if s.persistenceWalked == nil {
		s.persistenceWalked = make(map[string]bool)
	}
	if s.persistenceWalked[resolved] {
		return
	}
	_ = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, err error) error {
		return s.visitPersistencePath(absolute, resolved, path, entry, err)
	})
	s.persistenceWalked[resolved] = true
}

func persistenceEntrypointName(name string) bool {
	return strings.EqualFold(name, "main.js") || strings.EqualFold(name, "index.js") || strings.EqualFold(name, "cli.js")
}

func discoveredPersistenceEntrypoint(path string) bool {
	path = strings.ToLower(filepath.ToSlash(path))
	for _, suffix := range []string{
		"/resources/app/main.js", "/resources/app/out/main.js",
		"/@vscode/deviceid/dist/index.js",
		"/discord_desktop_core/index.js", "/npm/lib/cli.js",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (s *Scanner) visitPersistencePath(absolute, resolved, path string, entry os.DirEntry, err error) error {
	if err != nil {
		s.scanError(path, err)
		return nil
	}
	if entry.IsDir() {
		if s.skipNpmCache(path) || s.skipBrowserStorage(path) {
			return filepath.SkipDir
		}
		if s.persistenceWalked[path] {
			return filepath.SkipDir
		}
		return nil
	}
	// Most files cannot be persistence entrypoints. Reject them before
	// allocating or normalizing full paths.
	if !isPersistenceSidecar(entry.Name()) && !persistenceEntrypointName(entry.Name()) && !extraToolchainPath(path) {
		return nil
	}
	// Preserve the caller's path spelling so the ordinary home walk and
	// fixed-path checks share deduplication keys (e.g. macOS /var aliases).
	rel, err := filepath.Rel(resolved, path)
	if err != nil {
		s.scanError(path, err)
		return nil
	}
	path = filepath.Join(absolute, rel)
	if isPersistenceSidecar(entry.Name()) {
		if s.markPersistenceChecked(path) {
			s.checkRepoArtifactName(path, entry.Name())
		}
	} else if discoveredPersistenceEntrypoint(path) || extraToolchainPath(path) {
		s.checkApplicationFile(path)
	}
	return nil
}
