package scan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const GitScanTimeout = 2 * time.Minute

// Git is an explicit opt-in exception to filesystem-only inspection. These
// plumbing commands read raw objects, never check out code or apply filters.
// https://git-scm.com/docs/git-rev-list
// https://git-scm.com/docs/git-cat-file
func gitCommand(ctx context.Context, repo string, args ...string) *exec.Cmd {
	options := []string{"--no-pager", "--no-replace-objects", "--no-lazy-fetch",
		"-c", "core.hooksPath=" + os.DevNull, "-c", "core.fsmonitor=false",
		"-c", "protocol.allow=never", "-c", "core.commitGraph=false",
		// Without this, a scan running as a different user than the repo owner
		// reads NOTHING: git's ownership guard fails every command with
		// "detected dubious ownership", the repo is counted as found but never
		// scanned, and the report still looks clean. That is the normal case
		// for fleet deployment -- an MDM policy runs as root over user homes.
		//
		// safe.directory is only honoured from protected configuration, and the
		// hardening below deliberately removes the other two scopes
		// (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL=/dev/null), so -c is the only
		// remaining channel -- no caller can supply it from the environment.
		//
		// The guard exists to stop an untrusted repo's LOCAL config from being
		// honoured; the flags above already neutralise what that config could
		// abuse (hooks, fsmonitor, protocols, commit-graph), and local config is
		// needed regardless for object format, worktrees and alternates.
		"-c", "safe.directory=*", "-C", repo}
	cmd := exec.CommandContext(ctx, "git", append(options, args...)...)
	// Inherited GIT_DIR, object-directory overrides, config injection and trace
	// settings must not redirect the scan or write files. Local repo config is
	// still needed for object format, worktrees and alternates.
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "GIT_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C")
	cmd.WaitDelay = time.Second
	return cmd
}

// Retain useful errors without buffering arbitrary subprocess output.
type gitDiagnostic struct {
	text      []byte
	truncated bool
	bytes     int64
}

func (d *gitDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	d.bytes += int64(n)
	remaining := 8192 - len(d.text)
	if len(p) > remaining {
		d.truncated = true
	}
	if remaining > 0 {
		d.text = append(d.text, p[:min(remaining, len(p))]...)
	}
	return n, nil
}

func (s *Scanner) scanGitRepositories() {
	// PATH only. Hunting for another copy -- Homebrew, MacPorts, a vendored
	// one -- would mean a scan running as root executing a binary out of a
	// directory an unprivileged account can write to (/usr/local/bin is
	// world-writable by default on macOS), in a tool whose whole job is
	// looking for a local compromise. A too-old git is reported, not
	// worked around.
	path, err := exec.LookPath("git")
	if err != nil {
		s.gitScanError("git", fmt.Errorf("Git history inspection requires Git: %w", err))
		return
	}
	s.stats.GitPath = path
	s.recordGitVersion(path)
	seen := make(map[string]bool)
	if s.discovery != nil {
		for _, path := range s.discovery.git {
			s.checkGitRepository(path, seen)
		}
		s.reportGitCoverage()
		return
	}
	s.walkScanRoots(func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			s.scanError(path, err)
			return nil
		}
		if entry.Name() == ".git" {
			if isUVGitSentinel(path) {
				s.stats.GitCacheMarkersSkipped++
				return nil
			}
			s.checkGitRepository(filepath.Dir(path), seen)
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() && looksLikeBareGit(path) {
			s.checkGitRepository(path, seen)
			return filepath.SkipDir
		}
		return nil
	})
	s.reportGitCoverage()
}

// MinimumGitVersion is the first release carrying --no-lazy-fetch, which
// every command in this file passes. An older Git rejects the whole command
// line with exit 129 before it does anything, so repository discovery itself
// fails and not one repository is inspected -- while the file half of the
// scan completes normally and the report still looks like a verdict.
// GIT_NO_LAZY_FETCH is no substitute; it landed in the same release.
// https://github.com/git/git/blob/master/Documentation/RelNotes/2.45.0.adoc
var MinimumGitVersion = [2]int{2, 45}

// recordGitVersion runs the one Git command that predates every option this
// file relies on. It must stay a bare `git --version`: adding the hardening
// flags would make the probe fail on exactly the Git it exists to identify.
// Nothing is read, written or configured, so there is nothing to harden
// beyond dropping inherited GIT_* redirection.
func (s *Scanner) recordGitVersion(path string) {
	ctx, cancel := context.WithTimeout(context.Background(), GitScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "GIT_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "LC_ALL=C")
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		s.gitScanError(path, fmt.Errorf("Git version could not be determined: %w", err))
		return
	}
	s.stats.GitVersion = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "git version "))
}

// parseGitVersion reads the leading major.minor out of a reported version.
// Everything after them is build identity -- "2.39.5 (Apple Git-154)",
// "2.45.1.windows.1" -- which is worth recording and not worth comparing.
func parseGitVersion(version string) ([2]int, bool) {
	fields := strings.SplitN(version, ".", 3)
	if len(fields) < 2 {
		return [2]int{}, false
	}
	var parsed [2]int
	for i, field := range fields[:2] {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n < 0 {
			return [2]int{}, false
		}
		parsed[i] = n
	}
	return parsed, true
}

// gitTooOld reports whether a recorded version predates the minimum. known
// is false when the version string could not be read at all, which is a
// coverage failure rather than a verdict either way.
func gitTooOld(version string) (old, known bool) {
	parsed, ok := parseGitVersion(version)
	if !ok {
		return false, false
	}
	if parsed[0] != MinimumGitVersion[0] {
		return parsed[0] < MinimumGitVersion[0], true
	}
	return parsed[1] < MinimumGitVersion[1], true
}

// reportGitVersion is the loud half of the version check. It is deliberately
// gated on having found a repository: a machine with no repositories needed
// no Git, and failing it over a Git it never called would be noise.
//
// This is CRITICAL rather than a warning because of how it fails. The file
// half of the scan completes, the report reads like any other, and the exit
// status was clean -- a files-only verdict presented as a whole one. A scan
// that is trusted while its Git half never ran is worse than one that fails
// outright, so it is made impossible to miss.
func (s *Scanner) reportGitVersion() {
	if s.stats.GitRepositoriesFound == 0 || s.stats.GitVersion == "" {
		return
	}
	old, known := gitTooOld(s.stats.GitVersion)
	if !known {
		s.gitScanError(s.stats.GitPath, fmt.Errorf("Git version %q could not be compared against the required %d.%d", s.stats.GitVersion, MinimumGitVersion[0], MinimumGitVersion[1]))
		return
	}
	if !old {
		// Old enough to run every command, too old to be told what the objects
		// are called. That leaves the size-matched half of the history scan
		// working and the filename-gated half silently absent -- and the
		// absent half is the one that finds the config-append landing, whose
		// carrier is the victim's own build config and so has no fixed size.
		// Same failure shape as the case below, so the same severity: the
		// report otherwise reads like a whole history scan.
		if !gitPathsSupported(s.stats.GitVersion) {
			s.addFinding(Finding{Check: "git-too-old-for-filenames", Severity: SevCritical, Path: s.stats.GitPath,
				coverageCategory: "Git errors",
				Detail: fmt.Sprintf("%s reports Git %s, and Git %d.%d or newer is required to read the names of objects in history. Repository history was inspected by payload size and object identity only; the filename-gated checks -- injected build configs, propagation artifacts, .gitignore concealment, IDE task hooks -- did not run against history. Working-tree coverage is unaffected. Install a newer Git (on macOS, update the Xcode Command Line Tools) and scan again.",
					s.stats.GitPath, s.stats.GitVersion, GitObjectPathsVersion[0], GitObjectPathsVersion[1])})
		}
		return
	}
	s.addFinding(Finding{Check: "git-too-old", Severity: SevCritical, Path: s.stats.GitPath,
		coverageCategory: "Git errors",
		Detail: fmt.Sprintf("%s reports Git %s, and Git %d.%d or newer is required: every Git command this scan runs passes --no-lazy-fetch, which an older Git rejects before doing anything. No repository history was inspected. The rest of this report covers files only. Install a newer Git (on macOS, update the Xcode Command Line Tools) and scan again.",
			s.stats.GitPath, s.stats.GitVersion, MinimumGitVersion[0], MinimumGitVersion[1])})
}

// A Git scan that reached only some of the repositories it found is already a
// list of per-repository warnings, but nothing in that list says how much of
// the machine they add up to. GitUnscannableCriticalPercent is where the two
// stop being the same kind of result. Across a deployed fleet, ordinary
// breakage -- a broken ref, an unavailable object, a dead submodule -- sits
// under about 10% of a machine's repositories, while the machines whose Git
// scan meant nothing failed 80-100% of theirs. A quarter separates them with
// room on both sides, and it makes any machine that scanned none of the
// repositories it found critical regardless of how few it had: 0 of 2 is not
// a scan with gaps, it is no Git coverage at all.
const GitUnscannableCriticalPercent = 25

func (s *Scanner) reportGitCoverage() {
	// Named before the ratio: "the installed Git cannot run these commands"
	// is the cause of the 0/N the ratio is about to report.
	s.reportGitVersion()
	found, scanned := s.stats.GitRepositoriesFound, s.stats.GitRepositoriesScanned
	if found == 0 {
		// Not an error: repositories kept outside the scanned roots are
		// invisible until -root names them. It is still a warning, because a
		// Git scan that inspected no history must not be reported as a Git
		// scan that found nothing wrong.
		s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: "git",
			coverageCategory: "Git coverage",
			Detail:           "No Git repositories were found, so no Git history was inspected. Add -root for any repositories kept outside the scanned directories."})
		return
	}
	unscannable := found - scanned
	if unscannable*100 <= found*GitUnscannableCriticalPercent {
		return
	}
	s.addFinding(Finding{Check: "scan-incomplete", Severity: SevCritical, Path: "git",
		coverageCategory: "Git coverage",
		Detail: fmt.Sprintf("Git history coverage is unusable: %d of %d repositories (%d%%) could not be scanned, above the %d%% critical threshold. The failures are listed individually above; this machine's Git result does not describe its repositories.",
			unscannable, found, GitUnscannablePercent(found, scanned), GitUnscannableCriticalPercent)})
}

// GitUnscannablePercent is the share of the repositories found that the scan
// could not complete. Truncating integer division is deliberate: it can only
// understate the failure, and both callers already know a nonzero share is
// nonzero. Zero repositories found is reported on its own terms, not as 0%.
func GitUnscannablePercent(found, scanned int) int {
	if found <= 0 {
		return 0
	}
	return (found - scanned) * 100 / found
}

func looksLikeBareGit(path string) bool {
	if info, err := os.Stat(filepath.Join(path, "HEAD")); err != nil || !info.Mode().IsRegular() {
		return false
	}
	for _, name := range []string{"objects", "refs"} {
		if info, err := os.Stat(filepath.Join(path, name)); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

func gitSmallOutput(ctx context.Context, repo string, args ...string) (string, error) {
	cmd := gitCommand(ctx, repo, args...)
	var out, diagnostic gitDiagnostic
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	start := time.Now()
	runErr := cmd.Start()
	var disk DebugDiskIO
	if runErr == nil {
		runErr, disk = waitDebugGit(ctx, cmd)
	}
	recordGit(ctx, repo, args, start, out.bytes, diagnostic.bytes, runErr, disk)
	if err := runErr; err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(diagnostic.text)))
	}
	if out.truncated {
		return "", fmt.Errorf("git %s output exceeded limit", args[0])
	}
	return strings.TrimSuffix(string(out.text), "\n"), nil
}

func (s *Scanner) checkGitRepository(repo string, seen map[string]bool) {
	ctx, cancel := context.WithTimeout(context.Background(), GitScanTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, debugContextKey{}, s.debug)
	common, err := gitSmallOutput(ctx, repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err == nil {
		common, err = filepath.EvalSymlinks(common)
	}
	if err != nil {
		s.stats.GitRepositoriesFound++
		s.gitScanError(repo, fmt.Errorf("Git repository discovery failed: %w", err))
		return
	}
	if seen[common] {
		return
	}
	seen[common] = true // --all includes other worktrees' HEADs too
	s.stats.GitRepositoriesFound++
	s.log("checking Git refs/history: %s", repo)
	shallow, err := gitSmallOutput(ctx, repo, "rev-parse", "--is-shallow-repository")
	if err != nil {
		s.gitScanError(repo, err)
		return
	}
	if shallow == "true" {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: repo, Detail: "Shallow Git repository: scanning locally available history only; older history was not fetched."})
	}
	// Emitted even when the scan below fails: whatever history was reached
	// before the failure is still a real finding, and dropping it would make
	// a partial scan quieter than a complete one.
	defer s.flushGitHistory(repo)
	if err := s.scanGitObjects(ctx, repo); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("Git scan timed out after %s; history coverage is incomplete: %w", GitScanTimeout, ctx.Err())
		}
		s.gitScanError(repo, err)
		return
	}
	s.stats.GitRepositoriesScanned++
}

type gitBatch struct {
	ctx        context.Context
	repo, mode string
	started    time.Time
	measured   *debugGitRead
	cmd        *exec.Cmd
	input      io.WriteCloser
	output     *bufio.Reader
	diagnostic gitDiagnostic
}

func startGitBatch(ctx context.Context, repo, mode string) (*gitBatch, error) {
	b := &gitBatch{cmd: gitCommand(ctx, repo, "cat-file", mode), ctx: ctx, repo: repo, mode: mode, started: time.Now()}
	var err error
	b.input, err = b.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := b.cmd.StdoutPipe()
	if err != nil {
		b.input.Close()
		return nil, err
	}
	b.measured = &debugGitRead{Reader: output}
	b.output = bufio.NewReader(b.measured)
	b.cmd.Stderr = &b.diagnostic
	if err := b.cmd.Start(); err != nil {
		b.input.Close()
		output.Close()
		return nil, err
	}
	return b, nil
}

func (b *gitBatch) close() error {
	b.input.Close()
	waitErr, disk := waitDebugGit(b.ctx, b.cmd)
	recordGit(b.ctx, b.repo, []string{"cat-file", b.mode}, b.started, b.measured.bytes.Load(), b.diagnostic.bytes, waitErr, disk)
	if err := waitErr; err != nil {
		return fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(string(b.diagnostic.text)))
	}
	return nil
}

type gitObject struct {
	id, kind string
	size     int64
}

func (b *gitBatch) request(id string) (gitObject, error) {
	if _, err := fmt.Fprintln(b.input, id); err != nil {
		return gitObject{}, err
	}
	line, err := b.output.ReadString('\n')
	if err != nil {
		return gitObject{}, err
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != id {
		return gitObject{}, fmt.Errorf("unavailable or invalid Git object %s: %q", id, strings.TrimSpace(line))
	}
	size, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || size < 0 {
		return gitObject{}, fmt.Errorf("invalid Git object size: %q", line)
	}
	return gitObject{id, parts[1], size}, nil
}

func (s *Scanner) scanGitObjects(ctx context.Context, repo string) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	metadata, err := startGitBatch(ctx, repo, "--batch-check")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			cancel()
		}
		if err := metadata.close(); result == nil {
			result = err
		}
	}()
	contents, err := startGitBatch(ctx, repo, "--batch")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			cancel()
		}
		if err := contents.close(); result == nil {
			result = err
		}
	}()
	return s.walkGitObjects(ctx, repo, metadata, contents)
}

func (s *Scanner) walkGitObjects(ctx context.Context, repo string, metadata, contents *gitBatch) error {
	// Object paths are what make the filename-gated checks available in
	// history; see gitContentCandidate. They are only requested in the NUL
	// framing, never in the legacy space-joined form.
	args := []string{"rev-list", "--objects", "--all", "--no-object-names", "--missing=print"}
	paths := gitPathsSupported(s.stats.GitVersion)
	if paths {
		args = []string{"rev-list", "--objects", "--all", "-z", "--missing=print"}
	}
	cmd := gitCommand(ctx, repo, args...)
	var diagnostic gitDiagnostic
	cmd.Stderr = &diagnostic
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		output.Close()
		return err
	}
	started := time.Now()
	measured := &debugGitRead{Reader: output}
	lines := bufio.NewScanner(measured)
	if paths {
		// Records are NUL-terminated, so a path may contain anything --
		// spaces, newlines, an = -- without becoming ambiguous.
		lines.Split(scanNULRecords)
		lines.Buffer(make([]byte, 4096), 1<<16)
	} else {
		// Only object IDs are emitted. Avoid path/newline ambiguity entirely.
		lines.Buffer(make([]byte, 128), 1024)
	}
	missing := 0
	firstMissing := ""
	walk := s.walkLegacyRecords
	if paths {
		walk = s.walkNULRecords
	}
	scanErr := walk(lines, repo, metadata, contents, &missing, &firstMissing)
	if scanErr == nil {
		scanErr = lines.Err()
	}
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr, disk := waitDebugGit(ctx, cmd)
	recordGit(ctx, repo, args, started, measured.bytes.Load(), diagnostic.bytes, waitErr, disk)
	if scanErr != nil {
		return fmt.Errorf("Git object inspection failed: %w", scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("Git history enumeration failed: %w: %s", waitErr, strings.TrimSpace(string(diagnostic.text)))
	}
	if missing > 0 {
		return fmt.Errorf("Git history incomplete: %d missing object(s), first %s; available objects were inspected, missing objects were not fetched", missing, firstMissing)
	}
	return nil
}

// walkLegacyRecords reads the --no-object-names stream a Git older than
// GitObjectPathsVersion produces: one object ID per line, with missing objects
// prefixed by ?. No path is available, so every object is dispatched unnamed
// and only the size-matched half of the scan can run.
func (s *Scanner) walkLegacyRecords(lines *bufio.Scanner, repo string, metadata, contents *gitBatch, missing *int, firstMissing *string) error {
	for lines.Scan() {
		id := lines.Text()
		if strings.HasPrefix(id, "?") && validGitObjectID(id[1:]) {
			*missing++
			if *firstMissing == "" {
				*firstMissing = id[1:]
			}
			continue
		}
		if !validGitObjectID(id) {
			return fmt.Errorf("invalid Git object ID: %q", id)
		}
		if err := s.checkGitObject(repo, id, "", metadata, contents); err != nil {
			return err
		}
	}
	return nil
}

// scanNULRecords splits the -z stream. Each record is NUL-terminated and is
// either a bare object ID or a token=value pair belonging to the ID above it.
func scanNULRecords(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// walkNULRecords accumulates each object's metadata before acting on it: the
// ID arrives first and its path follows, so an object can only be dispatched
// once the next ID -- or the end of the stream -- proves its record complete.
func (s *Scanner) walkNULRecords(lines *bufio.Scanner, repo string, metadata, contents *gitBatch, missing *int, firstMissing *string) error {
	var id, path string
	var absent bool
	flush := func() error {
		if id == "" {
			return nil
		}
		current, currentPath, currentAbsent := id, path, absent
		id, path, absent = "", "", false
		if currentAbsent {
			*missing++
			if *firstMissing == "" {
				*firstMissing = current
			}
			return nil
		}
		return s.checkGitObject(repo, current, currentPath, metadata, contents)
	}
	for lines.Scan() {
		record := lines.Text()
		if record == "" {
			continue
		}
		// An object ID never contains =, so it is what starts a new record.
		if key, value, ok := strings.Cut(record, "="); ok {
			switch key {
			case "path":
				path = value
			case "missing":
				absent = value == "yes"
			}
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		if !validGitObjectID(record) {
			return fmt.Errorf("invalid Git object ID: %q", record)
		}
		id = record
	}
	return flush()
}

func validGitObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Only sized entries make a blob a hashing candidate. A size-less entry must
// never mean "hash every blob in every repository"; those hashes are matched
// on the filesystem by name instead, and that limit is reported to the user.
func gitHashCandidate(size int64) bool {
	return knownPayloadSize(size)
}

func (s *Scanner) checkGitObject(repo, id, path string, metadata, contents *gitBatch) error {
	object, err := metadata.request(id)
	if err != nil {
		return err
	}
	if object.kind != "blob" {
		return nil
	}
	s.stats.GitBlobsConsidered++
	// The object ID is already in hand, so a published blob identity is a free
	// match: no body read, no hashing, and it works for any size.
	if h, ok := knownPayloadBlob(id); ok {
		s.stats.GitBlobsIdentified++
		s.addGitPayloadFinding(repo, id,
			fmt.Sprintf("%s (attack: %s); matched by published Git object identity. Reachable from local refs/HEAD history; may be historical, not in the checkout.", h.Desc, h.Attack),
			fmt.Sprintf("blob %s", id))
		return nil
	}
	// Two independent reasons to read a body: a length that matches a sized
	// entry, which needs no name, and a name the filesystem walk would have
	// opened, which needs no size. A blob with neither is never read.
	sized := gitHashCandidate(object.size)
	name := ""
	if path != "" {
		name = filepath.Base(path)
	}
	named := gitContentCandidate(path, name)
	if !sized && !named {
		return nil
	}
	if object.size >= SignatureScanMaxBytes {
		return s.reportOversizedGitBlob(repo, sized)
	}
	data, err := readGitBlob(contents, object)
	if err != nil {
		return err
	}
	if sized {
		s.matchGitPayloadHash(repo, id, data)
	}
	if named {
		s.stats.GitBlobsInspected++
		s.inspectGitBlob(repo, path, id, data)
	}
	return nil
}

// A sized candidate over the limit is a coverage failure, because its length
// already matched a payload. An ordinary source blob over it is not: it is the
// same limit the filesystem walk applies, so it is reported as scope. The
// detail omits the blob ID so a repository with many oversized blobs states
// the limit once.
func (s *Scanner) reportOversizedGitBlob(repo string, sized bool) error {
	if sized {
		return fileSizeError()
	}
	s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: repo,
		Detail: "Git history: blobs at or above the content inspection limit were not read; name-gated history checks did not cover every blob in this repository."})
	return nil
}

// readGitBlob drains exactly one body off the --batch stream. The metadata the
// body announces must match what --batch-check reported, or the two streams
// are describing different objects and nothing after this point is trustworthy.
func readGitBlob(contents *gitBatch, object gitObject) ([]byte, error) {
	body, err := contents.request(object.id)
	if err != nil {
		return nil, err
	}
	if body != object {
		return nil, fmt.Errorf("Git object changed during inspection: %s", object.id)
	}
	data := make([]byte, body.size)
	if _, err := io.ReadFull(contents.output, data); err != nil {
		return nil, err
	}
	if end, err := contents.output.ReadByte(); err != nil || end != '\n' {
		return nil, fmt.Errorf("invalid Git object terminator: %s", object.id)
	}
	return data, nil
}

func (s *Scanner) matchGitPayloadHash(repo, id string, data []byte) {
	s.stats.GitBlobsChecked++
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for _, h := range KnownRepoPayloadHashes {
		if digest != h.SHA256 {
			continue
		}
		s.addGitPayloadFinding(repo, id,
			fmt.Sprintf("%s (attack: %s); matched by raw-content SHA-256. Reachable from local refs/HEAD history; may be historical, not in the checkout.", h.Desc, h.Attack),
			fmt.Sprintf("blob %s, SHA-256 %s", id, digest))
	}
}

// uv deliberately puts an empty .git and .gitignore in its sdist bucket.
// Do not suppress arbitrary invalid gitfiles or prune the bucket's contents.
// https://github.com/astral-sh/uv/blob/main/crates/uv-cache/src/lib.rs
func isUVGitSentinel(path string) bool {
	bucket := filepath.Dir(path)
	version, ok := strings.CutPrefix(filepath.Base(bucket), "sdists-v")
	if !ok {
		return false
	}
	if _, err := strconv.ParseUint(version, 10, 32); err != nil {
		return false
	}
	for _, marker := range []string{path, filepath.Join(bucket, ".gitignore")} {
		info, err := os.Lstat(marker)
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return false
		}
	}
	f, err := os.Open(filepath.Join(filepath.Dir(bucket), "CACHEDIR.TAG"))
	if err != nil {
		return false
	}
	defer f.Close()
	const signature = "Signature: 8a477f597d28d172789f06886806bc55"
	header := make([]byte, len(signature))
	_, err = io.ReadFull(f, header)
	return err == nil && string(header) == signature
}

func (s *Scanner) gitScanError(repo string, err error) {
	category := "Git errors"
	if strings.Contains(err.Error(), "timed out") {
		category = "timed out"
	}
	s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: repo,
		coverageCategory: category, Detail: err.Error()})
}
