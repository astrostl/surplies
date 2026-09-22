package scan

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func gitFixture(t *testing.T, repo string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, repo, args...)
	cmd.Env = append(cmd.Env, "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func initGitFixture(t *testing.T, parent, name string, extra ...string) string {
	t.Helper()
	repo := filepath.Join(parent, name)
	if err := os.MkdirAll(repo, 0700); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, append([]string{"init", "--initial-branch=main"}, extra...)...)
	return repo
}

func commitGitFixture(t *testing.T, repo, name, body string) {
	t.Helper()
	path := filepath.Join(repo, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, repo, "add", "--", name)
	gitFixture(t, repo, "-c", "commit.gpgSign=false", "commit", "-m", "inert fixture")
}

func fixtureHashList(t *testing.T) []string {
	t.Helper()
	previous := KnownRepoPayloadHashes
	t.Cleanup(func() { KnownRepoPayloadHashes = previous })
	bodies := []string{"inert test payload one", "inert second test payload"}
	KnownRepoPayloadHashes = nil
	for i, body := range bodies {
		KnownRepoPayloadHashes = append(KnownRepoPayloadHashes, RepoPayloadHash{
			Filename: fmt.Sprintf("expected-%d.js", i), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(body))), Size: int64(len(body)),
			GitBlobSHA1: fmt.Sprintf("%x", sha1.Sum(fmt.Appendf(nil, "blob %d\x00%s", len(body), body))),
			Desc:        "inert test fixture", Attack: "test",
		})
	}
	return bodies
}

func TestGitFindsHashesOutsideCheckout(t *testing.T) {
	bodies := fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "repo")
	commitGitFixture(t, repo, "clean.txt", "safe")
	gitFixture(t, repo, "checkout", "-b", "other")
	commitGitFixture(t, repo, "renamed/not-the-expected-name.dat", bodies[0])
	gitFixture(t, repo, "tag", "historical")
	commitGitFixture(t, repo, "renamed/not-the-expected-name.dat", "cleaned")
	gitFixture(t, repo, "update-ref", "refs/remotes/origin/poisoned", "HEAD")
	gitFixture(t, repo, "checkout", "main")
	gitFixture(t, repo, "branch", "-D", "other")
	gitFixture(t, repo, "checkout", "-b", "second")
	commitGitFixture(t, repo, "second.bin", bodies[1])
	gitFixture(t, repo, "tag", "second-only-tag")
	gitFixture(t, repo, "checkout", "main")
	gitFixture(t, repo, "branch", "-D", "second")
	gitFixture(t, repo, "gc", "--prune=now") // packed object coverage
	s := New(home, false)
	s.ExtraRoots = []string{repo} // overlap must not duplicate
	s.scanGitRepositories()
	hits := findingsFor(s, "git-payload-hash")
	if len(hits) != 2 {
		t.Fatalf("want 2 hashes from non-checked-out refs/history: %+v", s.Findings)
	}
	for _, f := range hits {
		if f.Severity != SevCritical || f.Path != repo || !strings.Contains(f.Detail, "blob ") {
			t.Fatalf("bad finding: %+v", f)
		}
	}
	if len(findingsFor(s, "scan-incomplete")) != 0 || s.stats.GitRepositoriesScanned != 1 {
		t.Fatalf("bad coverage: %+v %+v", s.stats, s.Findings)
	}
	if _, err := os.Stat(filepath.Join(repo, "second.bin")); !os.IsNotExist(err) {
		t.Fatal("scanner changed checkout")
	}
}

func TestGitIgnoresUnreachableObjectsAndFilenameCollisions(t *testing.T) {
	bodies := fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "repo")
	commitGitFixture(t, repo, "expected-0.js", strings.Repeat("x", len(bodies[0])))
	gitFixture(t, repo, "checkout", "-b", "discard")
	commitGitFixture(t, repo, "orphan.dat", bodies[0])
	gitFixture(t, repo, "checkout", "main")
	gitFixture(t, repo, "branch", "-D", "discard")
	s := New(home, false)
	s.scanGitRepositories()
	if len(s.Findings) != 0 || s.stats.GitRepositoriesScanned != 1 {
		t.Fatalf("unreachable blob must not count: %+v %+v", s.Findings, s.stats)
	}
}

func TestGitBareWorktreeAndSHA256(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			bodies := fixtureHashList(t)
			home := t.TempDir()
			repo := initGitFixture(t, home, "repo", "--object-format="+format)
			commitGitFixture(t, repo, "safe.txt", "safe")
			worktree := filepath.Join(home, "worktree")
			gitFixture(t, repo, "worktree", "add", "--detach", worktree, "HEAD")
			name := "odd name\nfile.dat"
			if runtime.GOOS == "windows" {
				name = "odd name file.dat"
			}
			commitGitFixture(t, worktree, name, bodies[0])
			s := New(worktree, false)
			s.scanGitRepositories()
			if len(findingsFor(s, "git-payload-hash")) != 1 {
				t.Fatalf("detached worktree: %+v", s.Findings)
			}
			// A blob-only tag, without a commit/path, is still reachable.
			oid := gitFixture(t, worktree, "rev-parse", "HEAD:"+name)
			gitFixture(t, repo, "update-ref", "refs/tags/blob-only", oid)
			bare := filepath.Join(home, "bare.git")
			gitFixture(t, home, "-c", "protocol.file.allow=always", "clone", "--bare", repo, bare)
			b := New(bare, false)
			b.scanGitRepositories()
			if len(findingsFor(b, "git-payload-hash")) != 1 || b.stats.GitRepositoriesScanned != 1 {
				t.Fatalf("bare: %+v %+v", b.Findings, b.stats)
			}
			all := New(home, false)
			all.scanGitRepositories()
			if all.stats.GitRepositoriesScanned != 2 {
				t.Fatalf("worktree deduplication: %+v %+v", all.stats, all.Findings)
			}
		})
	}
}

// Per-repository failures and the run-wide coverage verdict are both
// scan-incomplete records. A test about one must not silently pass on the
// other, so select by the category that distinguishes them.
func coverageFor(s *Scanner, category string) []Finding {
	var out []Finding
	for _, f := range findingsFor(s, "scan-incomplete") {
		if f.coverageCategory == category {
			out = append(out, f)
		}
	}
	return out
}

func TestGitEmptyAndBrokenRepositories(t *testing.T) {
	fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "empty")
	s := New(home, false)
	s.scanGitRepositories()
	if len(s.Findings) != 0 || s.stats.GitRepositoriesScanned != 1 {
		t.Fatalf("empty repo: %+v", s.Findings)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "refs", "heads", "broken"), []byte(strings.Repeat("1", 40)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s = New(home, false)
	s.scanGitRepositories()
	if len(coverageFor(s, "Git errors")) != 1 || s.stats.GitRepositoriesScanned != 0 {
		t.Fatalf("broken ref swallowed: %+v %+v", s.Findings, s.stats)
	}
	// 0 of 1 is not a scan with a gap in it; nothing was covered.
	verdict := coverageFor(s, "Git coverage")
	if len(verdict) != 1 || verdict[0].Severity != SevCritical || !strings.Contains(verdict[0].Detail, "1 of 1 repositories (100%)") {
		t.Fatalf("unscanned repository not escalated: %+v", s.Findings)
	}
}

func TestGitDoesNotFetchOrHonorEnvironmentRedirection(t *testing.T) {
	bodies := fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "repo")
	commitGitFixture(t, repo, "renamed.dat", bodies[0])
	t.Setenv("GIT_DIR", filepath.Join(home, "nonexistent"))
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "alias.rev-list")
	t.Setenv("GIT_CONFIG_VALUE_0", "!exit 99")
	s := New(home, false)
	s.scanGitRepositories()
	if len(findingsFor(s, "git-payload-hash")) != 1 {
		t.Fatalf("environment redirected scan: %+v", s.Findings)
	}
	// Simulate an unavailable promisor blob. The scanner must fail visibly,
	// without materializing it from the remote or invoking a remote helper.
	oid := gitFixture(t, repo, "rev-parse", "HEAD:renamed.dat")
	gitFixture(t, repo, "config", "remote.origin.promisor", "true")
	gitFixture(t, repo, "config", "remote.origin.url", "ext::touch SHOULD_NOT_EXIST")
	gitFixture(t, repo, "config", "protocol.ext.allow", "always")
	if err := os.Remove(filepath.Join(repo, ".git", "objects", oid[:2], oid[2:])); err != nil {
		t.Fatal(err)
	}
	s = New(home, false)
	s.scanGitRepositories()
	if len(coverageFor(s, "Git errors")) != 1 {
		t.Fatalf("missing blob swallowed: %+v", s.Findings)
	}
	if _, err := os.Stat(filepath.Join(repo, "SHOULD_NOT_EXIST")); !os.IsNotExist(err) {
		t.Fatal("remote helper executed")
	}
}

func TestGitMissingExecutableAndDeadline(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		s := New(t.TempDir(), false)
		s.scanGitRepositories()
		if len(findingsFor(s, "scan-incomplete")) != 1 {
			t.Fatal(s.Findings)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		repo := initGitFixture(t, t.TempDir(), "repo")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s := New(repo, false)
		if err := s.scanGitObjects(ctx, repo); err == nil {
			t.Fatal("cancellation ignored")
		}
	})
}

func TestGitShallowHistoryIsReported(t *testing.T) {
	fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "source")
	commitGitFixture(t, repo, "file", "first")
	commitGitFixture(t, repo, "file", "second")
	shallow := filepath.Join(home, "shallow")
	gitFixture(t, home, "-c", "protocol.file.allow=always", "clone", "--no-local", "--depth=1", repo, shallow)
	s := New(shallow, false)
	s.scanGitRepositories()
	coverage := findingsFor(s, "scan-limited")
	if len(coverage) != 1 || coverage[0].Severity != SevInfo || !strings.Contains(coverage[0].Detail, "Shallow") || len(findingsFor(s, "scan-incomplete")) != 0 {
		t.Fatalf("missing shallow coverage: %+v", s.Findings)
	}
}

func TestActivePayloadHashMetadata(t *testing.T) {
	seen := make(map[string]bool)
	for _, h := range KnownRepoPayloadHashes {
		if len(h.SHA256) != 64 || !validGitObjectID(h.SHA256) || seen[h.SHA256] {
			t.Fatalf("invalid/duplicate payload metadata: %+v", h)
		}
		// Two tiers: a sized entry is matched without trusting the filename;
		// a size-less entry must carry a filename, because it is name-gated
		// on disk and is deliberately not a Git blob candidate.
		if h.Size < 0 || h.Size >= SignatureScanMaxBytes {
			t.Fatalf("invalid size: %+v", h)
		}
		if h.Size == 0 && h.Filename == "" {
			t.Fatalf("size-less entry needs a filename: %+v", h)
		}
		if h.Size == 0 && gitHashCandidate(h.Size) {
			t.Fatalf("size-less entry must not be a Git candidate: %+v", h)
		}
		seen[h.SHA256] = true
		if h.GitBlobSHA1 != "" && (len(h.GitBlobSHA1) != 40 || !validGitObjectID(h.GitBlobSHA1)) {
			t.Fatalf("invalid Git identity: %+v", h)
		}
	}
}

func TestGitUVSentinelDoesNotHideRepositories(t *testing.T) {
	home := t.TempDir()
	bucket := filepath.Join(home, "uv", "sdists-v9")
	if err := os.MkdirAll(bucket, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".git", ".gitignore"} {
		if err := os.WriteFile(filepath.Join(bucket, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "uv", "CACHEDIR.TAG"), []byte("Signature: 8a477f597d28d172789f06886806bc55\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initGitFixture(t, bucket, "nested")
	s := New(home, false)
	s.scanGitRepositories()
	if len(s.Findings) != 0 || s.stats.GitCacheMarkersSkipped != 1 || s.stats.GitRepositoriesFound != 1 || s.stats.GitRepositoriesScanned != 1 {
		t.Fatalf("sentinel/nested: %+v %+v", s.Findings, s.stats)
	}
	if err := os.WriteFile(filepath.Join(bucket, ".git"), []byte("broken gitfile"), 0600); err != nil {
		t.Fatal(err)
	}
	s = New(home, false)
	s.scanGitRepositories()
	if len(coverageFor(s, "Git errors")) != 1 || s.stats.GitCacheMarkersSkipped != 0 {
		t.Fatalf("nonempty corrupt gitfile suppressed: %+v", s.Findings)
	}
	if err := os.WriteFile(filepath.Join(home, ".git"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if isUVGitSentinel(filepath.Join(home, ".git")) {
		t.Fatal("arbitrary empty gitfile suppressed")
	}
}

func TestGitMissingObjectStillScansAvailableBlobs(t *testing.T) {
	bodies := fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "repo")
	commitGitFixture(t, repo, "lost.txt", "unavailable unrelated data")
	commitGitFixture(t, repo, "match.dat", bodies[0])
	oid := gitFixture(t, repo, "rev-parse", "HEAD:lost.txt")
	if err := os.Remove(filepath.Join(repo, ".git", "objects", oid[:2], oid[2:])); err != nil {
		t.Fatal(err)
	}
	s := New(home, false)
	s.scanGitRepositories()
	if len(findingsFor(s, "git-payload-hash")) != 1 {
		t.Fatalf("available match missed: %+v", s.Findings)
	}
	coverage := coverageFor(s, "Git errors")
	if len(coverage) != 1 || !strings.Contains(coverage[0].Detail, oid) {
		t.Fatalf("missing object not reported: %+v", coverage)
	}
	// The fixture publishes a blob identity, so the match is free: identified
	// by object ID with no body read, hence zero candidate hashes.
	if s.stats.GitBlobsConsidered != 1 || s.stats.GitBlobsIdentified != 1 || s.stats.GitBlobsChecked != 0 || s.stats.GitRepositoriesScanned != 0 {
		t.Fatalf("bad counts: %+v", s.stats)
	}
}

func TestGitBlobsConsideredWithoutSizeCandidates(t *testing.T) {
	fixtureHashList(t)
	home := t.TempDir()
	repo := initGitFixture(t, home, "repo")
	commitGitFixture(t, repo, "clean.txt", "safe")
	s := New(home, false)
	s.scanGitRepositories()
	if s.stats.GitBlobsConsidered != 1 || s.stats.GitBlobsChecked != 0 {
		t.Fatalf("bad counts: %+v", s.stats)
	}
}

// The share of repositories a scan could not complete decides whether the run
// is a list of warnings or a result that describes nothing. The boundary is
// exercised on both sides, and zero repositories found is its own case: no
// history was inspected, so the run must not read as a clean Git scan.
func TestGitCoverageVerdictThresholds(t *testing.T) {
	for _, c := range []struct {
		name            string
		found, scanned  int
		want            Severity
		reported, exact string
	}{
		{name: "none found", want: SevWarn, reported: "Git coverage", exact: "No Git repositories were found"},
		{name: "all scanned", found: 9, scanned: 9},
		{name: "ordinary breakage", found: 9, scanned: 7},
		{name: "at the threshold", found: 100, scanned: 75},
		{name: "above the threshold", found: 100, scanned: 74, want: SevCritical, reported: "Git coverage", exact: "26 of 100 repositories (26%)"},
		{name: "none scanned", found: 2, want: SevCritical, reported: "Git coverage", exact: "2 of 2 repositories (100%)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := New(t.TempDir(), false)
			s.stats.GitRepositoriesFound, s.stats.GitRepositoriesScanned = c.found, c.scanned
			s.reportGitCoverage()
			if c.reported == "" {
				if len(s.Findings) != 0 {
					t.Fatalf("completed coverage reported as a gap: %+v", s.Findings)
				}
				return
			}
			got := coverageFor(s, c.reported)
			if len(got) != 1 || got[0].Severity != c.want || !strings.Contains(got[0].Detail, c.exact) {
				t.Fatalf("want one %s %s containing %q: %+v", c.want, c.reported, c.exact, s.Findings)
			}
		})
	}
}

// gitShim puts a stand-in for git first on PATH. It answers --version and
// rejects everything else with 129 and the message an older git prints,
// which is exactly how git < 2.45 behaves against --no-lazy-fetch: the
// option is top-level, so the whole command line fails before any repository
// is opened.
func gitShim(t *testing.T, version string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("PATH shim needs a shell script; the comparison itself is covered by TestGitVersionComparison")
	}
	bin := t.TempDir()
	path := filepath.Join(bin, "git")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '" + version + "'; exit 0; fi\n" +
		"echo 'error: unknown option: --no-lazy-fetch' >&2\nexit 129\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return path
}

// The failure this guards against is not a scan that breaks. It is a scan
// that completes, reports its file half, exits 0, and reads like a verdict
// while no repository was ever opened.
func TestGitTooOldIsCriticalAndNotAnIndicator(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "repo", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	shim := gitShim(t, "git version 2.39.5 (Apple Git-154)")
	s := New(home, false)
	s.scanGitRepositories()

	// Recorded on every run: without these the cause is only inferable from
	// an error string, and PATH differs between a hand-run and a daemon.
	if s.stats.GitPath != shim || s.stats.GitVersion != "2.39.5 (Apple Git-154)" {
		t.Fatalf("resolved git not recorded: %+v", s.stats)
	}
	old := findingsFor(s, "git-too-old")
	if len(old) != 1 || old[0].Severity != SevCritical || old[0].Path != shim {
		t.Fatalf("old git not reported critical: %+v", s.Findings)
	}
	for _, want := range []string{"2.39.5 (Apple Git-154)", "2.45 or newer is required", "covers files only"} {
		if !strings.Contains(old[0].Detail, want) {
			t.Fatalf("detail missing %q: %s", want, old[0].Detail)
		}
	}
	// Critical, but not a sign of an attack: it must be filed as coverage so
	// the report never claims this machine shows an indicator.
	indicators, coverage := splitFindings(s.Findings)
	if len(indicators) != 0 {
		t.Fatalf("coverage failure counted as an indicator: %+v", indicators)
	}
	if len(coverage) == 0 {
		t.Fatalf("no coverage records: %+v", s.Findings)
	}
	var summary strings.Builder
	s.stats.Git = true
	PrintReportSummary(&summary, s.Findings, s.stats, "surplies dev")
	if !strings.Contains(summary.String(), "*** GIT IS TOO OLD TO INSPECT REPOSITORIES! ***") {
		t.Fatalf("old git is not prominent: %s", summary.String())
	}
	if !strings.Contains(summary.String(), "Git binary: "+shim+" (version 2.39.5 (Apple Git-154))") {
		t.Fatalf("resolved git not stated: %s", summary.String())
	}
	if strings.Contains(summary.String(), "critical indicator(s)") {
		t.Fatalf("old git counted as an indicator: %s", summary.String())
	}
}

// A machine with no repositories needed no Git, and must not be failed over
// a Git it never called.
func TestGitTooOldWithoutRepositoriesIsNotCritical(t *testing.T) {
	gitShim(t, "git version 2.39.5 (Apple Git-154)")
	s := New(t.TempDir(), false)
	s.scanGitRepositories()
	if len(findingsFor(s, "git-too-old")) != 0 {
		t.Fatalf("failed a machine with no repositories: %+v", s.Findings)
	}
	if s.stats.GitVersion != "2.39.5 (Apple Git-154)" {
		t.Fatalf("version not recorded on a passing run: %+v", s.stats)
	}
}

// The real git on this machine has to be recorded too, and must not be
// reported as too old unless it is.
func TestGitVersionRecordedForTheInstalledGit(t *testing.T) {
	home := t.TempDir()
	initGitFixture(t, home, "repo")
	s := New(home, false)
	s.scanGitRepositories()
	if s.stats.GitPath == "" || s.stats.GitVersion == "" {
		t.Fatalf("installed git not recorded: %+v", s.stats)
	}
	old, known := gitTooOld(s.stats.GitVersion)
	if !known {
		t.Fatalf("unparseable version from the installed git: %q", s.stats.GitVersion)
	}
	if got := len(findingsFor(s, "git-too-old")); (got != 0) != old {
		t.Fatalf("version %q reported old=%v but produced %d finding(s)", s.stats.GitVersion, old, got)
	}
}

func TestGitVersionComparison(t *testing.T) {
	for _, c := range []struct {
		version    string
		old, known bool
	}{
		{version: "2.39.5 (Apple Git-154)", old: true, known: true},
		{version: "2.24.3 (Apple Git-128)", old: true, known: true},
		{version: "1.9.5", old: true, known: true},
		{version: "2.44.99", old: true, known: true},
		{version: "2.45.0", known: true},
		{version: "2.45.1.windows.1", known: true},
		{version: "2.50.1 (Apple Git-155)", known: true},
		{version: "3.0.0", known: true},
		{version: "10.0.0", known: true},
		{version: ""},
		{version: "2"},
		{version: "banana.split.1"},
		{version: "2.x.1"},
	} {
		t.Run(c.version, func(t *testing.T) {
			old, known := gitTooOld(c.version)
			if old != c.old || known != c.known {
				t.Fatalf("got old=%v known=%v, want old=%v known=%v", old, known, c.old, c.known)
			}
		})
	}
}
