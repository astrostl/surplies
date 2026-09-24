package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// Temp directories are walked like the home directory rather than probed at
// their top level. A dropper that unpacks into a subdirectory of $TMPDIR is
// invisible to a flat glob, and the staging paths published for these
// campaigns are only examples of where a run happened to land.
//
// Only the invoking user's temp directories are in scope. Other users'
// (/var/folders/*/*/T, /run/user/*, C:\Users\*\AppData\Local\Temp) require
// root and are a separate cross-user decision.
func DefaultTempRoots() []string {
	candidates := []string{os.TempDir()}
	switch runtime.GOOS {
	case "darwin":
		// $TMPDIR is /var/folders/<xx>/<hash>/T; its sibling holds files macOS
		// deletes at boot. confstr does not publish that one, so derive it.
		if base := os.TempDir(); filepath.Base(filepath.Clean(base)) == "T" {
			candidates = append(candidates, filepath.Join(filepath.Dir(filepath.Clean(base)), "Cleanup At Startup"))
		}
		candidates = append(candidates, "/tmp", "/var/tmp")
	case "windows":
		candidates = append(candidates, os.Getenv("TMP"))
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		candidates = append(candidates, filepath.Join(systemRoot, "Temp"))
	default:
		candidates = append(candidates, "/tmp", "/var/tmp", "/dev/shm")
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			runtimeDir = filepath.Join("/run/user", strconv.Itoa(os.Getuid()))
		}
		candidates = append(candidates, runtimeDir)
	}
	return candidates
}

// tempScanRoots is the deduplicated temp-directory list this run walks: every
// TempRoots candidate that exists, and only those inside a requested root under
// -only. The candidates are injected rather than read from the environment here
// so a test scan stays inside its fixture instead of walking the real machine. Paths are resolved, so /tmp and its /private/tmp target — or
// %TEMP% and %TMP% — are one root, not two walks.
func (s *Scanner) tempScanRoots() []string {
	if s.tempRoots != nil {
		return s.tempRoots
	}
	s.tempRoots = []string{}
	seen := make(map[string]bool)
	for _, candidate := range s.TempRoots {
		if candidate == "" {
			continue
		}
		absolute, resolved, err := resolveScanRoot(candidate)
		if err != nil {
			continue // absent or unreadable temp dir: nothing to walk
		}
		if seen[resolved] || !s.pathInScope(absolute) {
			continue
		}
		if s.SkipTempRoots && !s.rootRequested(absolute, resolved) {
			continue
		}
		seen[resolved] = true
		s.tempRoots = append(s.tempRoots, resolved)
		// The walk reports each path under the spelling its own root was given,
		// so a temp directory reached through another root (-root /tmp, or a
		// home that contains it) arrives spelled that way. Match both.
		s.tempSpellings = append(s.tempSpellings, resolved)
		if absolute != resolved {
			s.tempSpellings = append(s.tempSpellings, absolute)
		}
	}
	return s.tempRoots
}

// rootRequested reports whether a temp directory was named on the command line
// rather than added by default. -skip-tmproots drops the default temp roots, but
// -root names a directory explicitly and an explicit root has to keep its
// checks: a run given -root /tmp asked for that tree, so the staging-name
// matching still applies inside it. Under -only the first -root stands in for
// home, so HomeDir is an explicit root there and only there.
func (s *Scanner) rootRequested(absolute, resolved string) bool {
	requested := s.ExtraRoots
	if s.Only {
		requested = append([]string{s.HomeDir}, requested...)
	}
	for _, root := range resolvedScanRoots(requested) {
		if pathWithin(root, absolute) || pathWithin(root, resolved) {
			return true
		}
	}
	return false
}

// tempWalkRoots are the temp directories this run has to walk itself: one
// already inside home or a requested root is covered by that walk, and naming
// it again would list the same tree twice in the header.
func (s *Scanner) tempWalkRoots() []string {
	covered := resolvedScanRoots(append([]string{s.HomeDir}, s.ExtraRoots...))
	roots := make([]string, 0, len(s.tempScanRoots()))
	for _, root := range s.tempScanRoots() {
		if slices.ContainsFunc(covered, func(prior string) bool { return pathWithin(prior, root) }) {
			continue
		}
		roots = append(roots, root)
	}
	return roots
}

func (s *Scanner) tempRootFor(path string) string {
	s.tempScanRoots()
	for _, root := range s.tempSpellings {
		if pathWithin(root, path) {
			return root
		}
	}
	return ""
}

// visitTempArtifact matches the published temp staging names at every depth
// under a temp root. It rides the shared discovery walk rather than traversing
// the same trees a second time, so it must skip everything outside those roots:
// a visitor that descended everywhere would defeat the pruning the other
// visitors do in the home directory.
func (s *Scanner) visitTempArtifact(path string, entry os.DirEntry, err error) error {
	if err != nil || entry == nil {
		return nil
	}
	root := s.tempRootFor(path)
	if root == "" {
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if entry.IsDir() {
		return nil
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		return nil
	}
	for _, sp := range ArtifactsTmp {
		if tempArtifactMatch(rel, sp.Glob) {
			s.addTempArtifact(path, sp.Desc)
		}
	}
	return nil
}

func (s *Scanner) addTempArtifact(path, desc string) {
	s.stats.FilesChecked++
	s.addFinding(Finding{Check: "suspicious-temp-file", Severity: SevWarn, Path: path, Detail: desc})
}

// checkSkippedTempTops keeps the staging names checked at the top of each
// default temp directory that -skip-tmproots dropped from the walk. The flag
// exists to skip a costly recursive walk, not a handful of fixed lookups.
func (s *Scanner) checkSkippedTempTops() {
	if !s.SkipTempRoots {
		return
	}
	walked := s.tempScanRoots()
	seen := make(map[string]bool)
	for _, candidate := range s.TempRoots {
		if candidate == "" {
			continue
		}
		absolute, resolved, err := resolveScanRoot(candidate)
		if err != nil || seen[resolved] || slices.Contains(walked, resolved) || !s.pathInScope(absolute) {
			continue
		}
		seen[resolved] = true
		for _, sp := range ArtifactsTmp {
			matches, _ := filepath.Glob(filepath.Join(resolved, filepath.FromSlash(sp.Glob)))
			for _, path := range matches {
				if info, err := os.Lstat(path); err == nil && !info.IsDir() {
					s.addTempArtifact(path, sp.Desc)
				}
			}
		}
	}
}

// A published glob names the last path components of the artifact, not its
// position in the tree: match those components wherever they appear. Patterns
// are written with forward slashes; paths are not, on Windows.
func tempArtifactMatch(rel, glob string) bool {
	want := strings.Split(filepath.ToSlash(glob), "/")
	have := strings.Split(filepath.ToSlash(rel), "/")
	if len(have) < len(want) {
		return false
	}
	have = have[len(have)-len(want):]
	for i, pattern := range want {
		ok, err := filepath.Match(pattern, have[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}
