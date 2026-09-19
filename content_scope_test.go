package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRoutineContentScope(t *testing.T) {
	home := t.TempDir()
	marker := "/*RS260605*/"
	excluded := []string{"data/tokenizer.json", "game/audio.xml", "sessions/chat.json", "downloads/opaque", "documents/notes.txt", "loose/module.py", "loose/script.js", "project/data/settings.json", "project/data/hidden"}
	included := []string{"loose/index.js", "loose/tailwind.config.js", ".vscode/tasks.json", ".npm/_npx/env/node_modules/pkg/data.json"}
	for _, p := range append(append([]string{}, excluded...), included...) {
		writeFixture(t, filepath.Join(home, p), marker)
	}
	writeFixture(t, filepath.Join(home, ".npm/_npx/env/node_modules/pkg/package.json"), `{"main":"data.json"}`)
	writeFixture(t, filepath.Join(home, "project", "package.json"), `{"name":"test"}`)
	for _, all := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		s.Broad = all
		s.scanProjectDirs()
		found := map[string]bool{}
		for _, f := range findingsFor(s, "payload-signature") {
			found[f.Path] = true
		}
		for _, p := range included {
			if !found[filepath.Join(home, p)] {
				t.Errorf("all=%v lost coverage for %s", all, p)
			}
		}
		for _, p := range excluded {
			if found[filepath.Join(home, p)] != all {
				t.Errorf("all=%v unexpected scope for %s", all, p)
			}
		}
	}
}
func TestBrowserCachePrunedButExtensionsRetained(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, "Library", "Caches", "Microsoft Edge")
	writeFixture(t, filepath.Join(cache, "Profile 1", "Cache", "node_modules", "pkg", "index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(cache, "Profile 1/Cache/node_modules/pkg/package.json"), `{"main":"index.js"}`)
	extension := filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Default", "Extensions", "pkg", "Cache", "index.js")
	writeFixture(t, extension, "/*RS260605*/")
	for _, all := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		s.BrowserCache = all
		visited := false
		s.walkScanRoots(func(path string, d fs.DirEntry, err error) error {
			if path == cache {
				visited = true
			}
			return nil
		})
		s.scanProjectDirs()
		if visited != all {
			t.Fatalf("all=%v visited browser cache=%v", all, visited)
		}
		want := 1
		if all {
			want = 2
		}
		if got := len(findingsFor(s, "payload-signature")); got != want {
			t.Fatalf("got %d want %d: %v", got, want, s.Findings)
		}
	}
}
func TestUnrelatedDataZeroContentReads(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"tokenizer.json", "audio.xml", "opaque", "history.txt", "font.woff2"} {
		writeFixture(t, filepath.Join(home, "data", name), "/*RS260605*/")
	}
	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()
	if n := s.contentIO.bytes.Load(); n != 0 {
		t.Fatalf("unrelated data read %d bytes", n)
	}
}
func TestBroadExplicitAndExtraRoot(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	m := registerScanModes(f)
	if err := f.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	if m.Broad {
		t.Fatal("default enabled broad content")
	}
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "tailwind.config.js"), "/*RS260605*/")
	s := New(t.TempDir(), false)
	s.ExtraRoots = []string{root}
	s.scanProjectDirs()
	if len(findingsFor(s, "payload-signature")) != 1 {
		t.Fatal("explicit root did not find injection candidate")
	}
}

// Small inert corpus: browser objects and model data alongside source code.
// Run with -benchtime=1x for bounded before/after scope measurements.
func BenchmarkContentScope(b *testing.B) {
	home := b.TempDir()
	blob := bytes.Repeat([]byte("ordinary model data\n"), 2048)
	for _, dir := range []string{"models", "Library/Caches/Microsoft Edge/Profile 1/Cache"} {
		full := filepath.Join(home, dir)
		if err := os.MkdirAll(full, 0700); err != nil {
			b.Fatal(err)
		}
		for i := range 64 {
			if err := os.WriteFile(filepath.Join(full, fmt.Sprintf("%d.json", i)), blob, 0600); err != nil {
				b.Fatal(err)
			}
		}
	}
	code := filepath.Join(home, "index.js")
	if err := os.WriteFile(code, []byte("console.log('fixture');"), 0600); err != nil {
		b.Fatal(err)
	}
	for _, all := range []bool{true, false} {
		b.Run(fmt.Sprintf("all-content=%v", all), func(b *testing.B) {
			var total int64
			for i := 0; i < b.N; i++ {
				s := New(home, false)
				s.Deep = true
				s.Broad = all
				s.scanProjectDirs()
				total += s.contentIO.bytes.Load()
			}
			b.ReportMetric(float64(total)/float64(b.N), "read-bytes/op")
		})
	}
}

func TestHomeManifestDoesNotTurnHomeIntoProject(t *testing.T) {
	home := t.TempDir()
	manifest := `{"name":"home-tools"}`
	writeFixture(t, filepath.Join(home, "package.json"), manifest)
	// Dotfiles repositories must not accidentally broaden the scope either.
	if err := os.Mkdir(filepath.Join(home, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"Documents/curseforge/minecraft/Install/assets/objects/3c/3ce97077a760a299bf919e7d6464e451a852c670", "Library/data/tokenizer.json", "Downloads/data.xml", ".cache/opaque"} {
		writeFixture(t, filepath.Join(home, path), "/*RS260605*/")
	}
	projectManifest := `{"name":"actual-project"}`
	writeFixture(t, filepath.Join(home, "src/project/package.json"), projectManifest)
	writeFixture(t, filepath.Join(home, "src/project/tailwind.config.js"), "/*RS260605*/")
	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()
	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 || hits[0].Path != filepath.Join(home, "src/project/tailwind.config.js") {
		t.Fatalf("scope leaked or project lost: %v", hits)
	}
	want := int64(len(manifest) + len(projectManifest) + len("/*RS260605*/"))
	if got := s.contentIO.bytes.Load(); got != want {
		t.Fatalf("read %d bytes, selected files require %d", got, want)
	}
}

func TestProjectAndExplicitRootNeverSelectAllSource(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "src", "project")
	manifest := `{"name":"fixture"}`
	writeFixture(t, filepath.Join(project, "package.json"), manifest)
	// Every former blanket selection route: source extensions, data extensions,
	// extensionless executable, project membership and explicit extra root.
	for _, name := range []string{"bulk.js", "types.d.ts", "data.py", "data.json", "data.xml", "notes.md", "blob"} {
		path := filepath.Join(project, "assets", name)
		writeFixture(t, path, "/*RS260605*/")
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	candidate := filepath.Join(project, "tailwind.config.js")
	writeFixture(t, candidate, "/*RS260605*/")
	for _, extra := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		if extra {
			s.ExtraRoots = []string{project}
		}
		s.scanProjectDirs()
		hits := findingsFor(s, "payload-signature")
		if len(hits) != 1 || hits[0].Path != candidate {
			t.Fatalf("extra=%v selection leaked: %v", extra, hits)
		}
		want := int64(len(manifest) + len("/*RS260605*/"))
		if n := s.contentIO.bytes.Load(); n != want {
			t.Fatalf("extra=%v read %d want %d", extra, n, want)
		}
	}
}

func TestContentExpansionFlagsIndependent(t *testing.T) {
	home := t.TempDir()
	marker := "/*RS260605*/"
	paths := []string{"documents/notes.txt", "Library/Application Support/Google/Chrome/Default/Cache/nested/object", ".npm/_cacache/content-v2/object"}
	for _, path := range paths {
		writeFixture(t, filepath.Join(home, path), marker)
	}
	for mask := range 8 {
		t.Run(fmt.Sprintf("options-%d", mask), func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			modes := registerScanModes(flags)
			var args []string
			for bit, name := range []string{"-broad", "-browser-cache", "-npm-cache"} {
				if mask&(1<<bit) != 0 {
					args = append(args, name)
				}
			}
			if err := flags.Parse(args); err != nil {
				t.Fatal(err)
			}
			s := New(home, false)
			s.Deep, s.Broad, s.BrowserCache, s.NpmCache = modes.Deep, modes.Broad, modes.BrowserCache, modes.NpmCache
			s.scanProjectDirs()
			found := map[string]bool{}
			for _, finding := range findingsFor(s, "payload-signature") {
				found[finding.Path] = true
			}
			wantBytes := int64(0)
			for bit, path := range paths {
				want := mask&(1<<bit) != 0
				if found[filepath.Join(home, path)] != want {
					t.Errorf("%v: unexpected selection for %s", args, path)
				}
				if want {
					wantBytes += int64(len(marker))
				}
			}
			if got := s.contentIO.bytes.Load(); got != wantBytes {
				t.Fatalf("read %d bytes, want %d", got, wantBytes)
			}
		})
	}
}
