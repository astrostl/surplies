package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestSharedDiscoveryMatchesSeparateWalks(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, filepath.Join(home, "package.json"), `{"name":"home"}`)
	writeFixture(t, filepath.Join(home, "node_modules/demo/package.json"), `{"main":"index.js"}`)
	writeFixture(t, filepath.Join(home, "node_modules/demo/index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, "node_modules/demo/env/site-packages/litellm-1.82.7.dist-info/METADATA"), "Name: litellm\nVersion: 1.82.7\n")
	writeFixture(t, filepath.Join(home, "project/.git/HEAD"), "ref: refs/heads/main")
	writeFixture(t, filepath.Join(home, "Documents/decoy.js"), "/*RS260605*/")
	for i := range 100 {
		writeFixture(t, filepath.Join(home, fmt.Sprint("data/", i), "asset"), "unrelated")
	}
	for _, deep := range []bool{false, true} {
		old := New(home, false)
		old.Deep = deep
		old.debug = newScanDebug(io.Discard)
		old.scanProjectDirs()
		old.walkScanRoots(old.visitPython)
		// The third legacy phase enumerates directories independently.
		old.walkScanRoots(func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() && d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		})
		next := New(home, false)
		next.Deep = deep
		next.Git = true
		next.debug = newScanDebug(io.Discard)
		next.scanSharedDiscovery()
		for _, path := range next.discovery.python {
			next.visitPython(path, nil, nil)
		}
		keys := func(s *Scanner) []string {
			var out []string
			for _, f := range s.Findings {
				out = append(out, fmt.Sprint(f))
			}
			sort.Strings(out)
			return out
		}
		if !reflect.DeepEqual(keys(old), keys(next)) {
			t.Fatalf("deep=%v findings changed\nold %v\nnew %v", deep, keys(old), keys(next))
		}
		if len(next.discovery.git) != 1 {
			t.Fatalf("missing Git discovery: %v", next.discovery.git)
		}
		before, after := old.debug.snapshot().Traversal.Calls, next.debug.snapshot().Traversal.Calls
		if after*2 >= before {
			t.Fatalf("discovery not consolidated: %d -> %d", before, after)
		}
		t.Logf("deep=%v directory reads %d -> %d, same findings", deep, before, after)
	}
}

func TestContentReusePreservesChecksAndInvalidatesChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.js")
	writeFixture(t, path, "/*RS260605*/")
	s := New(filepath.Dir(path), false)
	check := func(id string) {
		s.processSourceFile(path, func(local *Scanner, data []byte) {
			local.addFinding(Finding{Check: id, Path: path, Detail: string(data)})
		})
	}
	check("first")
	check("second")
	if len(s.Findings) != 2 || s.contentIO.bytes.Load() != 12 {
		t.Fatalf("checks or reads: %+v bytes=%d", s.Findings, s.contentIO.bytes.Load())
	}
	writeFixture(t, path, "changed content")
	check("third")
	if s.contentIO.bytes.Load() != 27 || s.Findings[2].Detail != "changed content" {
		t.Fatal("stale content reused")
	}
	// Same size, different timestamp also invalidates.
	writeFixture(t, path, "another content")
	future := time.Now().Add(time.Second)
	os.Chtimes(path, future, future)
	check("fourth")
	if s.contentIO.bytes.Load() != 42 {
		t.Fatal("same-size edit reused")
	}
	// Distinct installations must be read independently.
	other := filepath.Join(t.TempDir(), "index.js")
	writeFixture(t, other, "another content")
	s.processSourceFile(other, nil)
	if s.contentIO.bytes.Load() != 57 {
		t.Fatal("distinct copy skipped")
	}
}

func TestContentCacheEvictionAndPolicies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.js")
	writeFixture(t, path, "plain source")
	s := New(filepath.Dir(path), false)
	s.debug = newScanDebug(io.Discard)
	s.processSourceFile(path, nil)
	s.processSourceFile(path, nil)
	f := s.debug.snapshot().Files[path]
	if f.Reads != 1 || f.CacheHits != 1 {
		t.Fatalf("wrong debug accounting: %+v", f)
	}
	// A prefix-oriented source read cannot satisfy a full-content policy.
	s.processFile(path, ReadTimeout, nil)
	if s.contentIO.bytes.Load() != 24 {
		t.Fatal("read policies incorrectly shared")
	}
	// Force eviction without imposing any limit on subsequent inspection.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s.reads.put("large", false, info, make([]byte, contentCacheBytes))
	s.processFile(path, ReadTimeout, nil)
	if s.contentIO.bytes.Load() != 36 {
		t.Fatal("eviction suppressed inspection")
	}
}

func TestSharedDiscoveryRootsAndGitBoundaries(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, filepath.Join(home, "repo/.git/HEAD"), "ref: refs/heads/main")
	writeFixture(t, filepath.Join(home, "linked/.git"), "gitdir: ../repo/.git")
	writeFixture(t, filepath.Join(home, "bare/HEAD"), "ref: refs/heads/main")
	for _, name := range []string{"bare/objects", "bare/refs"} {
		if err := os.MkdirAll(filepath.Join(home, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(home, ".npm/_cacache/hidden/.git/HEAD"), "ignored")
	// Python discovery historically includes nested environments even inside
	// locations pruned by the project and Git consumers.
	writeFixture(t, filepath.Join(home, "repo/.git/site-packages/litellm-1.82.7.dist-info/METADATA"), "Name: litellm")
	s := New(home, false)
	s.Deep = true
	s.Git = true
	s.ExtraRoots = []string{home, filepath.Join(home, "repo")}
	s.scanSharedDiscovery()
	if len(s.discovery.git) != 3 || len(s.discovery.python) != 1 {
		t.Fatalf("discovery: %+v", s.discovery)
	}
}
