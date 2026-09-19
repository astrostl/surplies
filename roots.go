package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Each scan phase walks home plus explicitly requested roots. Resolve root
// symlinks (e.g. /tmp), deduplicate overlapping roots, and retain the caller's
// path spelling in findings. Internal directory symlinks are not followed.
func (s *Scanner) walkScanRoots(visit fs.WalkDirFunc) {
	roots := append([]string{s.HomeDir}, s.ExtraRoots...)
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
		_ = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() && walked[path] {
				return filepath.SkipDir
			}
			display := path
			if absolute != resolved {
				display = absolute + strings.TrimPrefix(path, resolved)
			}
			return visit(display, entry, err)
		})
		walked[resolved] = true
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
		rel, err := filepath.Rel(prior, root)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
