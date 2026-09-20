package scan

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
	writeFixture(t, filepath.Join(extra, "vendor", "composer", "installed.json"), `{"packages":[{"name":"demo","autoload":{"files":["index.js"]}}]}`)
	writeFixture(t, filepath.Join(extra, "node_modules/demo/package.json"), `{"main":"index.js"}`)
	writeFixture(t, filepath.Join(extra, "venv/site-packages/demo-1.0.dist-info/entry_points.txt"), "[console_scripts]\ndemo = demo.index:main\n")
	// Python entrypoints use Python modules, not unrelated JavaScript files.
	writeFixture(t, filepath.Join(extra, "venv/site-packages/demo/index.py"), "/*RS260605*/")

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
		help := DefaultScanHelp(goos, roots)
		if goos == "windows" {
			if len(roots) != 2 || roots[0] != env["ProgramFiles"] || !strings.Contains(help, "%USERPROFILE%") || strings.Contains(help, "/Applications") {
				t.Fatalf("bad Windows defaults: %s", help)
			}
		} else if !strings.Contains(help, "Default full scan: ~") || strings.Contains(help, "D:") {
			t.Fatalf("bad Unix defaults: %s", help)
		}
		if strings.Contains(help, "/Applications") != (goos == "darwin") {
			t.Fatalf("wrong application root: %s", help)
		}
	}
}

// A tree reachable only through a directory link is absent from the scan.
// Say so once, for links that leave every root, and stay quiet for links that
// point back inside one (no coverage is lost) or resolve to a file.
func TestUnfollowedDirectoryLinksReportScope(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeFixture(t, filepath.Join(outside, "repo", "index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, "inside", "index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(home, "file.txt"), "fixture")
	links := map[string]string{
		"away":     outside,
		"internal": filepath.Join(home, "inside"),
		"tofile":   filepath.Join(home, "file.txt"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(home, name)); err != nil {
			t.Skip(err)
		}
	}
	s := New(home, false)
	s.scanProjectDirs()
	s.scanProjectDirs() // repeated walks must not repeat the notice
	notices := findingsFor(s, "scan-limited")
	var reported []string
	for _, f := range notices {
		if strings.Contains(f.Detail, "Directory link not followed") {
			reported = append(reported, f.Path)
		}
	}
	if len(reported) != 1 || reported[0] != filepath.Join(home, "away") {
		t.Fatalf("wrong unfollowed-link notices: %+v", notices)
	}
	if reported := findingsFor(s, "scan-incomplete"); len(reported) != 0 {
		t.Fatalf("scope reported as failure: %+v", reported)
	}
}
