package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtraRootRunsNormalChecksAndHonorsDeep(t *testing.T) {
	home := t.TempDir()
	extra := t.TempDir()
	writeFixture(t, filepath.Join(extra, "repo", "public", "fake.woff2"), "var payload = 'not a font';")
	writeFixture(t, filepath.Join(extra, "repo", "node_modules", "axios", "package.json"), `{"name":"axios","version":"1.14.1"}`)
	writeFixture(t, filepath.Join(extra, "venv", "site-packages", "litellm-1.82.7.dist-info", "METADATA"), "Name: litellm\nVersion: 1.82.7\n")
	for _, dependency := range []string{"node_modules/demo", "vendor/demo", "venv/site-packages/demo"} {
		writeFixture(t, filepath.Join(extra, dependency, "index.js"), "/*RS260605*/")
	}
	writeFixture(t, filepath.Join(extra, "vendor", "composer", "installed.json"), `{"packages":[]}`)
	for _, deep := range []bool{false, true} {
		s := New(home, false)
		s.ExtraRoots = []string{extra, extra, filepath.Join(extra, "repo")}
		s.Deep = deep
		s.scanProjectDirs()
		s.scanPythonPackages()
		for _, check := range []string{"fake-font-payload", "compromised-version", "compromised-python-version"} {
			if len(findingsFor(s, check)) != 1 {
				t.Fatalf("deep=%v check=%s: %+v", deep, check, s.Findings)
			}
		}
		want := 0
		if deep {
			want = 3
		}
		if got := len(findingsFor(s, "payload-signature")); got != want {
			t.Fatalf("deep=%v wanted %d dependency findings, got %d", deep, want, got)
		}
	}
}

func TestExtraRootSymlinkAndAncestorDeduplicate(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	writeFixture(t, filepath.Join(home, "fake.woff2"), "var fake = true;")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(parent, link); err != nil {
		t.Skip(err)
	}
	s := New(home, false)
	s.ExtraRoots = []string{link, parent, home}
	s.scanProjectDirs()
	if got := len(findingsFor(s, "fake-font-payload")); got != 1 {
		t.Fatalf("duplicate or missing finding: %d", got)
	}
}

func TestInvalidExtraRootsReportCoverage(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "ordinary.txt")
	writeFixture(t, file, "fixture")
	s := New(home, false)
	s.ExtraRoots = []string{filepath.Join(home, "missing"), file}
	s.scanProjectDirs()
	if len(findingsFor(s, "scan-incomplete")) != 2 {
		t.Fatalf("invalid roots reported clean: %+v", s.Findings)
	}
}

func TestPlatformDefaultRootsAndHelp(t *testing.T) {
	env := map[string]string{"ProgramFiles": `D:\Apps`, "ProgramFiles(x86)": `D:\Apps (x86)`}
	getenv := func(key string) string { return env[key] }
	for _, goos := range []string{"windows", "darwin", "linux"} {
		roots := persistenceRootsForOS(goos, getenv)
		help := defaultScanHelp(goos, roots)
		if goos == "windows" {
			if len(roots) != 2 || roots[0] != env["ProgramFiles"] || !strings.Contains(help, "%USERPROFILE%") || strings.Contains(help, "/Applications") {
				t.Fatalf("bad Windows defaults: %s", help)
			}
		} else if !strings.Contains(help, "Default normal scan: ~") || strings.Contains(help, "D:") {
			t.Fatalf("bad Unix defaults: %s", help)
		}
		if strings.Contains(help, "/Applications") != (goos == "darwin") {
			t.Fatalf("wrong application root: %s", help)
		}
	}
}
