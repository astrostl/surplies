package scan

import (
	"bytes"
	"strings"
	"testing"
)

func TestGitObjectPathVersionGate(t *testing.T) {
	for _, c := range []struct {
		version   string
		supported bool
	}{
		{version: "2.45.0"},
		{version: "2.47.1"},
		{version: "2.49.9"},
		{version: "2.39.5 (Apple Git-154)"},
		{version: "2.50.0", supported: true},
		{version: "2.50.1 (Apple Git-155)", supported: true},
		{version: "2.55.0", supported: true},
		{version: "3.0.0", supported: true},
		{version: ""},
		{version: "banana.split.1"},
	} {
		t.Run(c.version, func(t *testing.T) {
			if got := gitPathsSupported(c.version); got != c.supported {
				t.Fatalf("gitPathsSupported(%q) = %v, want %v", c.version, got, c.supported)
			}
		})
	}
}

// A Git that cannot emit object paths must still run the half of the history
// scan that needs no name, and must run it through the legacy parser rather
// than failing. What it must not do is quietly report the same coverage as a
// Git that can: the filename-gated checks are exactly the ones that find the
// config-append landing.
func TestGitLegacyModeScansSizesButNotNames(t *testing.T) {
	for _, c := range []struct {
		name          string
		version       string
		wantArtifact  bool
		wantInspected bool
	}{
		{name: "2.47.0 cannot emit paths", version: "2.47.0"},
		{name: "2.50.0 can", version: "2.50.0", wantArtifact: true, wantInspected: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			bodies := fixtureHashList(t)
			home := t.TempDir()
			repo := initGitFixture(t, home, "repo")
			// Findable by size alone, under a name no check knows.
			commitGitFixture(t, repo, "unremarkable.dat", bodies[0])
			// Findable by name alone, and only once paths are available.
			commitGitFixture(t, repo, "temp_auto_push.bat", "@echo off\r\n")
			// Deleted from the checkout: history is the only place left.
			gitFixture(t, repo, "rm", "-q", "--", "temp_auto_push.bat", "unremarkable.dat")
			gitFixture(t, repo, "-c", "commit.gpgSign=false", "commit", "-m", "cleaned up")

			s := New(home, false)
			s.stats.GitVersion = c.version
			s.checkGitRepository(repo, map[string]bool{})

			if len(findingsFor(s, "git-payload-hash")) != 1 {
				t.Fatalf("size-matched blob must be found in both modes: %+v", s.Findings)
			}
			if got := len(findingsFor(s, "malicious-repo-artifact")) > 0; got != c.wantArtifact {
				t.Fatalf("artifact found = %v, want %v: %+v", got, c.wantArtifact, s.Findings)
			}
			if got := s.stats.GitBlobsInspected > 0; got != c.wantInspected {
				t.Fatalf("blobs inspected = %d, want any = %v", s.stats.GitBlobsInspected, c.wantInspected)
			}
			if s.stats.GitRepositoriesScanned != 1 || len(findingsFor(s, "scan-incomplete")) != 0 {
				t.Fatalf("legacy parsing must not break the scan: %+v %+v", s.stats, s.Findings)
			}
		})
	}
}

// Counts alone would let an older Git's partial history scan read as a whole
// one. The summary has to name the half that did not run.
func TestGitLegacyModeStatesTheMissingHalf(t *testing.T) {
	for _, c := range []struct {
		version string
		want    bool
	}{
		{version: "2.47.0", want: true},
		{version: "2.55.0"},
		// Too old to run any of it; the existing critical says so instead.
		{version: "2.39.5 (Apple Git-154)"},
	} {
		t.Run(c.version, func(t *testing.T) {
			var out bytes.Buffer
			stats := ScanStats{Git: true, GitPath: "/usr/bin/git", GitVersion: c.version, GitRepositoriesFound: 1, GitRepositoriesScanned: 1}
			printGitSummary(&out, stats)
			if got := strings.Contains(out.String(), "cannot emit object paths"); got != c.want {
				t.Fatalf("scope line present = %v, want %v:\n%s", got, c.want, out.String())
			}
		})
	}
}

// A Git that can run every command but cannot name objects leaves the report
// looking like a complete history scan. That has to be as loud as a Git that
// inspects nothing, and it has to stay a coverage failure rather than being
// counted among the machine's attack indicators.
func TestGitWithoutObjectPathsIsCritical(t *testing.T) {
	for _, c := range []struct {
		version               string
		found                 int
		wantNames, wantTooOld bool
	}{
		{version: "2.47.0", found: 1, wantNames: true},
		{version: "2.45.0", found: 1, wantNames: true},
		{version: "2.50.0", found: 1},
		{version: "2.55.0", found: 1},
		{version: "2.39.5 (Apple Git-154)", found: 1, wantTooOld: true},
		// No repositories means no Git was needed; failing it would be noise.
		{version: "2.47.0"},
	} {
		t.Run(c.version+"/"+itoaFound(c.found), func(t *testing.T) {
			s := New(t.TempDir(), false)
			s.stats.GitPath = "/usr/bin/git"
			s.stats.GitVersion = c.version
			s.stats.GitRepositoriesFound = c.found
			s.reportGitVersion()
			names := findingsFor(s, "git-too-old-for-filenames")
			tooOld := findingsFor(s, "git-too-old")
			if (len(names) > 0) != c.wantNames || (len(tooOld) > 0) != c.wantTooOld {
				t.Fatalf("names=%d tooOld=%d, want names=%v tooOld=%v", len(names), len(tooOld), c.wantNames, c.wantTooOld)
			}
			for _, f := range names {
				if f.Severity != SevCritical || f.coverageCategory != "Git errors" {
					t.Fatalf("must be a critical coverage failure, not an indicator: %+v", f)
				}
				if !isCoverageCheck(f.Check) {
					t.Fatalf("%s must not count as an attack indicator", f.Check)
				}
			}
		})
	}
}

func itoaFound(n int) string {
	if n == 0 {
		return "no-repos"
	}
	return "repos"
}
