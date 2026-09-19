package main

import (
	"flag"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestNpmCacheExcludedBeforeTraversal(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, ".npm", "_cacache")
	writeFixture(t, filepath.Join(cache, "content-v2", "sha512", "blob"), "/*RS260605*/")
	writeFixture(t, filepath.Join(cache, "nested", "node_modules", "axios", "package.json"), `{"name":"axios","version":"1.14.1"}`)
	for _, deep := range []bool{false, true} {
		s := New(home, false)
		s.Deep = deep
		s.Git = true
		visits := 0
		s.walkScanRoots(func(path string, d fs.DirEntry, err error) error {
			if path == cache || rootCovered(path, map[string]bool{cache: true}) {
				visits++
			}
			return nil
		})
		s.scanProjectDirs()
		// A second phase must not create duplicate scope notices.
		s.walkPersistenceRoot(home)
		if visits != 0 || s.contentIO.bytes.Load() != 0 {
			t.Fatalf("cache traversed/read: visits=%d bytes=%d", visits, s.contentIO.bytes.Load())
		}
		if len(s.Findings) != 1 || s.Findings[0].Check != "scan-limited" {
			t.Fatalf("wrong cache diagnostics: %v", s.Findings)
		}
	}
}
func TestNpmCacheOptInAndRunnableCaches(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, filepath.Join(home, ".npm", "_cacache", "content-v2", "blob"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, ".npm", "_npx", "env", "node_modules", "pkg", "index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, "tool", "cache", "uv", "archive-v0", "pkg", "module.py"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, ".codex", "plugins", "cache", "plugin", "plugin.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, ".npm/_npx/env/node_modules/pkg/package.json"), `{"main":"index.js"}`)
	for _, include := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		s.NpmCache = include
		s.scanProjectDirs()
		want := 2 // Unreferenced extracted uv source is no longer content-scanned.
		if include {
			want++
		}
		if got := len(findingsFor(s, "payload-signature")); got != want {
			t.Fatalf("raw-cache=%v got %d: %v", include, got, s.Findings)
		}
	}
}
func TestDefaultDoesNotEnableNpmCache(t *testing.T) {
	for _, args := range [][]string{{}, {"-npm-cache"}} {
		flags := flag.NewFlagSet("test", flag.ContinueOnError)
		m := registerScanModes(flags)
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		if !m.Deep || !m.Git || !m.Coverage || m.NpmCache != (len(args) == 1) {
			t.Fatalf("incorrect modes for %v: %+v", args, m)
		}
	}
}
func TestExplicitCacheRootStillNeedsOptIn(t *testing.T) {
	home, cache := t.TempDir(), filepath.Join(t.TempDir(), "_cacache")
	writeFixture(t, filepath.Join(cache, "blob"), "/*RS260605*/")
	s := New(home, false)
	s.ExtraRoots = []string{cache}
	s.Deep = true
	s.scanProjectDirs()
	if s.contentIO.bytes.Load() != 0 {
		t.Fatal("explicit cache root bypassed cache policy")
	}
	s = New(home, false)
	s.ExtraRoots = []string{cache}
	s.NpmCache = true
	s.scanProjectDirs()
	if len(findingsFor(s, "payload-signature")) != 1 {
		t.Fatal("explicit opt-in did not work")
	}
}
