package main

import (
	"flag"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSelectsEvidenceInsteadOfDependencyBodies(t *testing.T) {
	home := t.TempDir()
	pkg := filepath.Join(home, "node_modules", "pkg")
	manifest := `{"main":"entry.cjs","bin":{"tool":"cli.js"},"exports":{".":{"types":"./types.d.ts","import":"./entry.mjs"},"./*":"./lib/*.js"},"scripts":{"postinstall":"node setup.js"}}`
	writeFixture(t, filepath.Join(pkg, "package.json"), manifest)
	for _, p := range []string{"entry.cjs", "cli.js", "entry.mjs", "setup.js"} {
		writeFixture(t, filepath.Join(pkg, p), "/*RS260605*/")
	}
	// Decoys deliberately contain the same indicator. They must not be read:
	// their contents do not participate in a selected check.
	body := strings.Repeat("ordinary declaration data\n", 4096) + "/*RS260605*/"
	for _, p := range []string{"types.d.ts", "lib/unreferenced.js", "data.json"} {
		writeFixture(t, filepath.Join(pkg, p), body)
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	m := registerScanModes(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	if !m.Deep || !m.Git || !m.Coverage {
		t.Fatal("default checks are disabled")
	}
	s := New(home, false)
	s.Deep = m.Deep
	s.scanProjectDirs()
	if got := len(findingsFor(s, "payload-signature")); got != 4 {
		t.Fatalf("selected entrypoints: %d %v", got, s.Findings)
	}
	want := int64(len(manifest) + 4*len("/*RS260605*/"))
	if got := s.contentIO.bytes.Load(); got != want {
		t.Fatalf("read %d bytes, selected evidence requires %d", got, want)
	}
}
func TestPythonDeepReadsOnlyDeclaredCommandModule(t *testing.T) {
	home := t.TempDir()
	sp := filepath.Join(home, "site-packages")
	writeFixture(t, filepath.Join(sp, "pkg-1.0.dist-info/entry_points.txt"), "[console_scripts]\nrun = pkg.cli:main\n")
	writeFixture(t, filepath.Join(sp, "pkg/cli.py"), "/*RS260605*/")
	writeFixture(t, filepath.Join(sp, "pkg/data.py"), strings.Repeat("data = 0\n", 8192)+"/*RS260605*/")
	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()
	// Use the fixture package directory directly, avoiding system Python discovery.
	s.inspectPythonEntrypoints(sp, "pkg-1.0.dist-info")
	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 || hits[0].Path != filepath.Join(sp, "pkg/cli.py") {
		t.Fatalf("wrong selection: %v", hits)
	}
	if s.contentIO.bytes.Load() > 1024 {
		t.Fatal("read unrelated Python bodies")
	}
}

func TestNonStringEntrypointDoesNotDisablePackageChecks(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "package.json"), `{"name":"axios","version":"1.14.1","main":false,"module":false}`)
	s := New(root, false)
	s.Deep = true
	s.checkPackage(root, "axios")
	if len(findingsFor(s, "scan-incomplete")) != 0 || len(findingsFor(s, "compromised-version")) != 1 {
		t.Fatalf("entrypoint field broke metadata checks: %v", s.Findings)
	}
}
