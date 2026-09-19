package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Only selected directories survive discovery; we do not retain a home-sized
// inventory of every file. Each consumer keeps its original pruning rules.
type scanDiscovery struct{ python, git []string }

type discoveryVisitor struct {
	skip  string
	visit func(string, os.DirEntry, error) error
}

func (v *discoveryVisitor) apply(path string, entry os.DirEntry, err error) bool {
	if v.skip != "" && strings.HasPrefix(path, v.skip+string(filepath.Separator)) {
		return false
	}
	v.skip = ""
	if v.visit(path, entry, err) == filepath.SkipDir && entry != nil && entry.IsDir() {
		v.skip = path
		return false
	}
	return true
}
func (s *Scanner) scanSharedDiscovery() {
	s.discovery = &scanDiscovery{}
	visitors := []*discoveryVisitor{{visit: s.visitProject}, {visit: s.discoverPython}}
	if s.Git {
		visitors = append(visitors, &discoveryVisitor{visit: s.discoverGit})
	}
	s.walkScanRoots(func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			s.scanError(path, err)
			return nil
		}
		descend := false
		for _, visitor := range visitors {
			if visitor.apply(path, entry, err) {
				descend = true
			}
		}
		if !descend && entry != nil && entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
}
func (s *Scanner) discoverPython(path string, entry os.DirEntry, err error) error {
	if err != nil || !entry.IsDir() {
		return nil
	}
	if entry.Name() == "site-packages" {
		s.discovery.python = append(s.discovery.python, path)
		return s.descendOrSkip()
	}
	return nil
}
func (s *Scanner) discoverGit(path string, entry os.DirEntry, err error) error {
	if err != nil {
		return nil
	}
	if entry.Name() == ".git" {
		if isUVGitSentinel(path) {
			s.stats.GitCacheMarkersSkipped++
			return nil
		}
		s.discovery.git = append(s.discovery.git, filepath.Dir(path))
		if entry.IsDir() {
			return filepath.SkipDir
		}
	} else if entry.IsDir() && looksLikeBareGit(path) {
		s.discovery.git = append(s.discovery.git, path)
		return filepath.SkipDir
	}
	return nil
}
