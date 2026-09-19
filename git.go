package main

import (
	"bufio"
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
		"-c", "protocol.allow=never", "-c", "core.commitGraph=false", "-C", repo}
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
	if _, err := exec.LookPath("git"); err != nil {
		s.gitScanError("git", fmt.Errorf("Git history inspection requires Git: %w", err))
		return
	}
	seen := make(map[string]bool)
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
	cmd := gitCommand(ctx, repo, "rev-list", "--objects", "--all", "--no-object-names", "--missing=print")
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
	// Only object IDs are emitted. Avoid path/newline ambiguity entirely.
	lines.Buffer(make([]byte, 128), 1024)
	var scanErr error
	missing := 0
	firstMissing := ""
	for lines.Scan() {
		id := lines.Text()
		if strings.HasPrefix(id, "?") && validGitObjectID(id[1:]) {
			missing++
			if firstMissing == "" {
				firstMissing = id[1:]
			}
			continue
		}
		if !validGitObjectID(id) {
			scanErr = fmt.Errorf("invalid Git object ID: %q", id)
			break
		}
		if scanErr = s.checkGitObject(repo, id, metadata, contents); scanErr != nil {
			break
		}
	}
	if scanErr == nil {
		scanErr = lines.Err()
	}
	if scanErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr, disk := waitDebugGit(ctx, cmd)
	recordGit(ctx, repo, []string{"rev-list", "--objects", "--all", "--no-object-names", "--missing=print"}, started, measured.bytes.Load(), diagnostic.bytes, waitErr, disk)
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

func validGitObjectID(id string) bool {
	if len(id) != 40 && len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func gitHashCandidate(size int64) bool {
	for _, h := range KnownRepoPayloadHashes {
		if h.Size == 0 || h.Size == size {
			return true
		}
	}
	return false
}

func (s *Scanner) checkGitObject(repo, id string, metadata, contents *gitBatch) error {
	object, err := metadata.request(id)
	if err != nil {
		return err
	}
	if object.kind != "blob" {
		return nil
	}
	s.stats.GitBlobsConsidered++
	if !gitHashCandidate(object.size) {
		return nil
	}
	if object.size >= SignatureScanMaxBytes {
		return fileSizeError()
	}
	body, err := contents.request(id)
	if err != nil {
		return err
	}
	if body != object {
		return fmt.Errorf("Git object changed during inspection: %s", id)
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, contents.output, body.size); err != nil {
		return err
	}
	if end, err := contents.output.ReadByte(); err != nil || end != '\n' {
		return fmt.Errorf("invalid Git object terminator: %s", id)
	}
	s.stats.GitBlobsChecked++
	digest := hex.EncodeToString(hash.Sum(nil))
	for _, h := range KnownRepoPayloadHashes {
		if digest != h.SHA256 {
			continue
		}
		s.addFinding(Finding{Check: "git-payload-hash", Severity: SevCritical, Path: repo,
			Detail: fmt.Sprintf("%s: blob %s, SHA-256 %s (attack: %s). Reachable from local refs/HEAD history; may be historical, not in the checkout. Inspect with git log --all --find-object=%s.", h.Desc, id, digest, h.Attack, id)})
	}
	return nil
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
