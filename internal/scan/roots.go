package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Shared discovery walks home plus explicitly requested roots. Resolve root
// symlinks (e.g. /tmp), deduplicate overlapping roots, and retain the caller's
// path spelling in findings. Internal directory symlinks are not followed.
func (s *Scanner) walkScanRoots(visit fs.WalkDirFunc) {
	roots := append([]string{s.HomeDir}, s.ExtraRoots...)
	targets := resolvedScanRoots(roots)
	walked := make(map[string]bool)
	for _, root := range roots {
		absolute, resolved, err := resolveScanRoot(root)
		if err != nil {
			s.scanError(root, err)
			continue
		}
		if rootCovered(resolved, walked) {
			continue
		}
		_ = s.walkClassified(resolved, absolute, s.rootVisitor(absolute, resolved, walked, targets, visit))
		walked[resolved] = true
	}
}

// One walk callback per root: translate the resolved path back to the caller's
// spelling, apply the traversal boundaries, then hand the entry to the caller.
func (s *Scanner) rootVisitor(absolute, resolved string, walked map[string]bool, targets []string, visit fs.WalkDirFunc) fs.WalkDirFunc {
	return func(path string, entry os.DirEntry, err error) error {
		display := path
		if absolute != resolved {
			display = absolute + strings.TrimPrefix(path, resolved)
		}
		if err != nil {
			return visit(display, entry, err)
		}
		if entry.IsDir() && walked[path] {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if s.skipNpmCache(display) || s.skipBrowserStorage(display) {
				return filepath.SkipDir
			}
			s.debug.event("walk", display, 0, 0)
		} else if entry.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			s.noteUnfollowedDirLink(display, path, targets)
		}
		return visit(display, entry, err)
	}
}

func resolveScanRoot(root string) (absolute, resolved string, err error) {
	absolute, err = filepath.Abs(root)
	if err != nil {
		return
	}
	resolved, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return
	}
	info, statErr := os.Stat(resolved)
	if statErr != nil {
		err = statErr
		return
	}
	if !info.IsDir() {
		err = fmt.Errorf("scan root must be a directory")
	}
	return
}

func rootCovered(root string, walked map[string]bool) bool {
	for prior := range walked {
		if pathWithin(prior, root) {
			return true
		}
	}
	return false
}

func pathWithin(prior, path string) bool {
	rel, err := filepath.Rel(prior, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Roots that resolve; an unresolvable root reports its own error during the walk.
func resolvedScanRoots(roots []string) []string {
	targets := make([]string, 0, len(roots))
	for _, root := range roots {
		if _, resolved, err := resolveScanRoot(root); err == nil {
			targets = append(targets, resolved)
		}
	}
	return targets
}

// Directory symlinks and Windows junctions are not followed, so a tree reachable
// only through one is absent from the scan with nothing on screen to say so.
// That is scope, not a failure: report it once per link, and only when the
// target sits outside every scan root, since a link pointing back inside a root
// hides no coverage.
func (s *Scanner) noteUnfollowedDirLink(display, path string, targets []string) {
	if s.linkNotices[display] {
		return
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return // broken or unreadable link: no tree was in scope to miss
	}
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		return
	}
	for _, root := range targets {
		if pathWithin(root, target) {
			return
		}
	}
	if s.linkNotices == nil {
		s.linkNotices = make(map[string]bool)
	}
	s.linkNotices[display] = true
	s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: display, Detail: "Directory link not followed: this path is a symlink or junction pointing outside every scan root, so the tree behind it was not scanned; pass that target with -root to include it"})
}

// Raw npm object stores are not installed packages; archive contents are not
// unpacked by this scanner. This explicit storage boundary does not cover _npx,
// node_modules, executable plugin caches or extracted uv environments.
// https://docs.npmjs.com/cli/v11/commands/npm-cache/
func (s *Scanner) skipNpmCache(path string) bool {
	if s.NpmCache || filepath.Base(path) != "_cacache" {
		return false
	}
	if s.rawCacheSkipped == nil {
		s.rawCacheSkipped = make(map[string]bool)
	}
	key := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		key = resolved
	}
	if !s.rawCacheSkipped[key] {
		s.rawCacheSkipped[key] = true
		s.log("skipping raw npm object cache: %s (use -npm-cache to include)", path)
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: path, Detail: "Raw npm _cacache storage excluded from traversal and content/Git inspection; use -npm-cache to include. Installed dependencies and npx installations remain in scope"})
	}
	return true
}

// Match filepath.WalkDir callback/skip semantics while reusing each directory
// listing for project classification. Internal symlinks remain unfollowed.
func (s *Scanner) walkClassified(root, displayRoot string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		return visit(root, nil, err)
	}
	var walk func(string, os.DirEntry) error
	walk = func(path string, entry os.DirEntry) error {
		if err := visit(path, entry, nil); err != nil || !entry.IsDir() {
			if err == filepath.SkipDir && entry.IsDir() {
				return nil
			}
			return err
		}
		entries, err := s.readDir(path)
		if err != nil {
			if err = visit(path, entry, err); err != nil {
				if err == filepath.SkipDir {
					return nil
				}
				return err
			}
		}
		s.classifyContentDir(displayRoot+strings.TrimPrefix(path, root), entries)
		for _, child := range entries {
			err := walk(filepath.Join(path, child.Name()), child)
			if err == filepath.SkipDir {
				break
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	err = walk(root, fs.FileInfoToDirEntry(info))
	if err == filepath.SkipAll || err == filepath.SkipDir {
		return nil
	}
	return err
}
