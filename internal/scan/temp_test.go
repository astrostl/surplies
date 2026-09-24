package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func evalDir(t *testing.T, dir string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// A dropper that unpacks into a subdirectory of $TMPDIR was invisible while
// temp directories were probed with a single flat glob. The published staging
// path is an example of where one run landed, not the only place the name can
// appear, so the name has to match at any depth.
func TestTempArtifactsFoundAtEveryDepth(t *testing.T) {
	home := evalDir(t, t.TempDir())
	temp := evalDir(t, t.TempDir())

	writeFixture(t, filepath.Join(temp, "pglog"), "payload")
	writeFixture(t, filepath.Join(temp, "npm-install-3f2a", "nested", "deeper", "tpcp.tar.gz"), "payload")
	writeFixture(t, filepath.Join(temp, "staging", "b-1234", "b.zip"), "payload")
	// Same names inside home are not temp staging and must not be reported by
	// this check.
	writeFixture(t, filepath.Join(home, "project", "pglog"), "payload")

	s := New(home, false)
	s.TempRoots = []string{temp}
	s.Run()

	found := make(map[string]bool)
	for _, f := range s.Findings {
		if f.Check == "suspicious-temp-file" {
			found[f.Path] = true
		}
	}
	for _, want := range []string{
		filepath.Join(temp, "pglog"),
		filepath.Join(temp, "npm-install-3f2a", "nested", "deeper", "tpcp.tar.gz"),
		filepath.Join(temp, "staging", "b-1234", "b.zip"),
	} {
		if !found[want] {
			t.Errorf("missed temp artifact %s; found %v", want, found)
		}
	}
	if found[filepath.Join(home, "project", "pglog")] {
		t.Error("home file reported as a temp artifact")
	}
}

// The temp visitor rides the shared discovery walk. If it descended outside the
// temp roots it would override the pruning the other visitors do, and a home
// walk would read every directory on the machine.
func TestTempVisitorSkipsDirectoriesOutsideTempRoots(t *testing.T) {
	home := evalDir(t, t.TempDir())
	temp := evalDir(t, t.TempDir())
	s := New(home, false)
	s.TempRoots = []string{temp}

	entries, err := os.ReadDir(filepath.Dir(home))
	if err != nil {
		t.Fatal(err)
	}
	var dir os.DirEntry
	for _, e := range entries {
		if e.IsDir() && filepath.Join(filepath.Dir(home), e.Name()) == home {
			dir = e
		}
	}
	if dir == nil {
		t.Fatal("home directory entry not found")
	}
	if got := s.visitTempArtifact(home, dir, nil); got != filepath.SkipDir {
		t.Errorf("visitTempArtifact(%s) = %v, want SkipDir", home, got)
	}
	if got := s.visitTempArtifact(temp, dir, nil); got != nil {
		t.Errorf("visitTempArtifact(%s) = %v, want descend", temp, got)
	}
}

// /tmp and /private/tmp are one directory, and on Windows %TEMP% and %TMP% are
// normally the same. Walking it twice doubles the cost of the phase and reports
// each finding under two spellings.
func TestTempScanRootsDeduplicatesAndDropsAbsentRoots(t *testing.T) {
	temp := evalDir(t, t.TempDir())
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(temp, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	s := New(t.TempDir(), false)
	s.TempRoots = []string{temp, link, temp, filepath.Join(temp, "absent")}
	if got := s.tempScanRoots(); len(got) != 1 || got[0] != temp {
		t.Errorf("tempScanRoots() = %v, want [%s]", got, temp)
	}
}

// -only means nothing outside the named roots is read. A temp directory is a
// fixed machine path, so it joins the run only when it falls inside one.
func TestTempScanRootsRespectOnly(t *testing.T) {
	temp := evalDir(t, t.TempDir())
	s := New(evalDir(t, t.TempDir()), false)
	s.Only = true
	s.TempRoots = []string{temp}
	if got := s.tempScanRoots(); len(got) != 0 {
		t.Errorf("tempScanRoots() under -only = %v, want none", got)
	}

	inScope := New(temp, false)
	inScope.Only = true
	inScope.TempRoots = []string{temp}
	if got := inScope.tempScanRoots(); len(got) != 1 {
		t.Errorf("requested temp root under -only = %v, want it kept", got)
	}
}

// The platform list is what makes the walk first-class; a missing entry is a
// directory nothing else in the scan reaches.
func TestDefaultTempRootsCoverThePlatform(t *testing.T) {
	roots := DefaultTempRoots()
	joined := strings.Join(roots, string(filepath.ListSeparator))
	var want []string
	switch runtime.GOOS {
	case "darwin":
		want = []string{os.TempDir(), "/tmp", "/var/tmp"}
	case "windows":
		want = []string{os.TempDir(), "Temp"}
	default:
		want = []string{os.TempDir(), "/tmp", "/var/tmp", "/dev/shm", "/run/user"}
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("DefaultTempRoots() = %v, missing %s", roots, w)
		}
	}
}

// -skip-tmproots drops the default temp directories from the walk. It narrows
// traversal rather than putting temp out of scope, so the run has to say what
// it stopped looking for.
func TestSkipTempRootsDropsDefaultTempWalk(t *testing.T) {
	home := evalDir(t, t.TempDir())
	temp := evalDir(t, t.TempDir())
	writeFixture(t, filepath.Join(temp, "npm-install-3f2a", "tpcp.tar.gz"), "payload")
	writeFixture(t, filepath.Join(temp, ".pg_state"), "state")
	writeFixture(t, filepath.Join(temp, "b-4c1e", "b.zip"), "zip")

	s := New(home, false)
	s.TempRoots = []string{temp}
	s.SkipTempRoots = true
	s.Run()

	if got := s.tempScanRoots(); len(got) != 0 {
		t.Errorf("tempScanRoots() with -skip-tmproots = %v, want none", got)
	}
	// Only the top of the temp directory is still checked: the nested
	// archive needs the walk, the top-level names do not.
	var got []string
	for _, f := range findingsFor(s, "suspicious-temp-file") {
		got = append(got, f.Path)
	}
	slices.Sort(got)
	want := []string{filepath.Join(temp, ".pg_state"), filepath.Join(temp, "b-4c1e", "b.zip")}
	if !slices.Equal(got, want) {
		t.Errorf("temp artifacts with -skip-tmproots = %v, want %v", got, want)
	}
	notices := findingsFor(s, "scan-limited")
	if !slices.ContainsFunc(notices, func(f Finding) bool { return f.Path == "temp" }) {
		t.Errorf("no temp scope notice with -skip-tmproots; got %v", notices)
	}
}

// An explicit -root is a directory the user asked for by name. -skip-tmproots
// drops the defaults, so suppressing the staging-name matching inside a tree
// that was named anyway would silently remove a check from requested scope.
func TestSkipTempRootsKeepsRequestedTempRoot(t *testing.T) {
	temp := evalDir(t, t.TempDir())
	writeFixture(t, filepath.Join(temp, "npm-install-3f2a", "tpcp.tar.gz"), "payload")

	s := New(evalDir(t, t.TempDir()), false)
	s.ExtraRoots = []string{temp}
	s.TempRoots = []string{temp}
	s.SkipTempRoots = true
	s.Run()

	if got := s.tempScanRoots(); len(got) != 1 || got[0] != temp {
		t.Fatalf("requested temp root with -skip-tmproots = %v, want [%s]", got, temp)
	}
	want := filepath.Join(temp, "npm-install-3f2a", "tpcp.tar.gz")
	if !slices.ContainsFunc(findingsFor(s, "suspicious-temp-file"), func(f Finding) bool { return f.Path == want }) {
		t.Errorf("missed staging artifact under a requested temp root: %v", s.Findings)
	}
}

// The scope notice belongs to the flag, not to the platform: a default run
// walks temp and must not claim otherwise.
func TestDefaultRunHasNoTempScopeNotice(t *testing.T) {
	s := New(evalDir(t, t.TempDir()), false)
	s.TempRoots = []string{evalDir(t, t.TempDir())}
	s.Run()
	for _, f := range findingsFor(s, "scan-limited") {
		if f.Path == "temp" {
			t.Errorf("temp scope notice on a default run: %+v", f)
		}
	}
}
