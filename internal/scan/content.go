package scan

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Content-based checks. Every other check in surplies matches on a path, a
// filename, or a declared version. These match on bytes inside a file, which
// is necessary for attacks that inject into a file that is supposed to exist
// and is supposed to have that name — PolinRider appends its loader to a real
// `tailwind.config.js` and hides a JavaScript loader inside a real-looking
// `fa-solid-400.woff2`. Neither is findable by name.
//
// Everything here is read-only and bounded: files are opened, at most
// SignatureScanMaxBytes are read, and nothing is executed, parsed as code, or
// written back.

// fontMagics are the leading bytes of each font container format. A file whose
// name claims to be a font but whose bytes match none of these is not a font.
var fontMagics = [][]byte{
	[]byte("wOF2"),           // WOFF2
	[]byte("wOFF"),           // WOFF
	[]byte("OTTO"),           // OpenType with CFF outlines
	[]byte("ttcf"),           // TrueType collection
	[]byte("true"),           // legacy Mac TrueType
	[]byte("typ1"),           // legacy Mac Type 1
	{0x00, 0x01, 0x00, 0x00}, // TrueType
	{0x80, 0x01},             // PFB (Type 1 binary)
	[]byte("%!PS-AdobeFont"), // Type 1 ASCII
	[]byte("\x1fsttf"),       // rare compressed TrueType wrapper
}

// fontExtensions are the extensions the fake-font check applies to.
var fontExtensions = []string{".woff2", ".woff", ".ttf", ".otf"}

// paddingRun is the literal space run that marks a whitespace-padded
// injection, built once from ConfigPaddingRunLength.
var paddingRun = strings.Repeat(" ", ConfigPaddingRunLength)

// injectableSourceNames are exact filenames a documented attack has been
// observed injecting a payload into, beyond the `*.config.*` pattern.
// From OSM's infected-file-type table (occurrence counts across a corpus of
// 1,736 compromised repos) plus the babel.config.cjs variant documented in
// their npm case study.
// https://github.com/OpenSourceMalware/PolinRider
// `plugin.js` is the NullReceiver carrier name — bianira-ui ships its loader as
// an appended top-level IIFE in the package main, named plugin.js because the
// package poses as a Tailwind plugin.
// https://osv.dev/vulnerability/MAL-2026-11132
//
// These historical entrypoint names remain eligible alongside the broader
// extension policy. Default dependency boundaries still apply to ordinary
// content; installed package scripts and targeted persistence are exceptions.
var injectableSourceNames = []string{
	"App.js",
	"index.js",
	"truffle.js",
	"tasks.json",
	"cli.js",
	"plugin.js",
}

// Eligibility is independent of traversal. Sources, text/config, extensionless
// files and supported disguised assets are inspected with the shared bounds.
// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts
func shouldScanForSignatures(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == "" || slices.Contains(SignatureScannedExtensions, ext) || assetExtension(ext) || slices.Contains(injectableSourceNames, name) || slices.ContainsFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.Filename == name })
}

func isJSFamily(ext string) bool {
	switch ext {
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx":
		return true
	}
	return false
}

// ReadTimeout bounds reading and content inspection together for one file.
//
// A file under Dropbox, OneDrive, iCloud Drive, or Google Drive may exist as a
// placeholder whose contents are not on local disk. Opening one asks the
// provider to fetch it. Usually that works and the file should be scanned —
// cloud-synced folders hold real repositories, and skipping them outright would
// be a blind spot in exactly the place this campaign spreads. But when the
// provider is not running, the account is unlinked, or the file is no longer
// available server-side, the read blocks indefinitely and then fails. The same
// happens on a stalled NFS or SMB mount.
//
// A timeout covers both: healthy placeholders download and get scanned, broken
// ones cost a few seconds and are reported. Four MiB from a local disk is
// effectively instant, so this only ever fires on something genuinely stuck.
const ReadTimeout = 5 * time.Second

// StallThreshold is how many reads may time out under one subtree before that
// subtree is abandoned for the rest of the scan.
//
// A timeout alone bounds each individual file but not the scan. An offline
// Dropbox folder holding a few hundred build configs would cost
// ReadTimeout × every one of them — technically not a hang, practically still
// unusable. Three strikes is enough to distinguish "one odd file" from "this
// whole mount is not answering", and caps the damage at
// StallThreshold × ReadTimeout per subtree.
const StallThreshold = 3

// stallKeyDepth is how many path components below the home directory identify
// a subtree for stall tracking. Three resolves the cloud-provider layouts that
// matter — `Library/CloudStorage/Dropbox`, `Library/CloudStorage/OneDrive-Foo`
// — without lumping all of `Library` together, and degrades sensibly elsewhere
// (`~/Dropbox` keys on itself; `~/src/project` keys per project).
const stallKeyDepth = 3

// stallKey identifies the subtree a path belongs to for stall tracking.
func (s *Scanner) stallKey(path string) string {
	rel, err := filepath.Rel(s.HomeDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		// Outside the home directory (e.g. a global npm install): key on the
		// containing directory.
		return filepath.Dir(path)
	}

	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) > stallKeyDepth {
		parts = parts[:stallKeyDepth]
	} else if len(parts) > 1 {
		parts = parts[:len(parts)-1] // drop the filename
	}
	return filepath.Join(s.HomeDir, filepath.Join(parts...))
}

// stalled reports whether a subtree has already been abandoned.
func (s *Scanner) stalled(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stallCounts[key] >= StallThreshold
}

// recordStall reports the first timed-out read in a subtree. Reaching the
// threshold abandons further reads there, without emitting duplicate findings.
//
// The finding is deliberately a finding and not a log line: it lands in the
// JSON output, it appears in the findings list, and it pushes the exit code off
// zero. A scan that silently gave up on a synced folder full of repositories
// must never be reportable as a clean scan — which is the same failure mode as
// a rate-limited API sweep returning empty results and being read as "nothing
// there".
func (s *Scanner) recordStall(key, path string) {
	s.mu.Lock()
	s.stats.FilesUnreadable++
	if s.stallCounts == nil {
		s.stallCounts = make(map[string]int)
	}
	s.stallCounts[key]++
	first := s.stallCounts[key] == 1
	s.mu.Unlock()

	s.log("file processing timed out after %s, not fully scanned: %s", ReadTimeout, path)

	if first {
		s.addFinding(Finding{
			Check:            "scan-incomplete",
			coverageCategory: "timed out",
			Severity:         SevWarn,
			Path:             key,
			Detail: fmt.Sprintf(
				"File reading or inspection under this path timed out; coverage is incomplete. After %d timeouts of %s each, further reads under this path are skipped. "+
					"Usually an offline or unlinked cloud-sync folder (Dropbox/OneDrive/iCloud/Drive) or a stalled network mount. "+
					"Bring it online and re-run to cover it.",
				StallThreshold, ReadTimeout),
		})
	}
}

// readCapped is the read-only form of the same per-file processing deadline.
func (s *Scanner) readCapped(path string) []byte {
	return s.processFile(path, ReadTimeout, nil)
}

var errFileTooLarge = errors.New("file size limit exceeded")

type fileResult struct {
	data          []byte
	findings      []Finding
	stats         ScanStats
	scriptChecked map[string]bool
	err           error
}

// Reading and inspection share one deadline. A private scanner collects results
// so a timed-out worker can never append findings after the parent has moved on.
func (s *Scanner) processFile(path string, timeout time.Duration, inspect func(*Scanner, []byte)) []byte {
	return s.processFileMode(path, timeout, inspect, false)
}

// Optional absent package manifests are not failures. The open still happens
// inside the same deadline; selected project manifests use optional=false.
func (s *Scanner) processFileMode(path string, timeout time.Duration, inspect func(*Scanner, []byte), optional bool) []byte {
	return s.processFilePolicy(path, timeout, inspect, optional, false)
}

// General source checks can reject binary prefixes. Targeted entrypoints,
// package metadata, lifecycle targets and exact-hash candidates retain full reads.
func (s *Scanner) processSourceFile(path string, inspect func(*Scanner, []byte)) []byte {
	source := !slices.ContainsFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.Filename == filepath.Base(path) })
	return s.processFilePolicy(path, ReadTimeout, inspect, false, source)
}
func (s *Scanner) processFilePolicy(path string, timeout time.Duration, inspect func(*Scanner, []byte), optional, source bool) []byte {
	s.debug.selection(path)
	key := s.stallKey(path)
	if s.stalled(key) {
		s.mu.Lock()
		s.stats.FilesUnreadable++
		s.mu.Unlock()
		return nil
	}
	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	cancel := make(chan struct{})
	defer close(cancel)
	var opened atomic.Pointer[os.File]
	done := make(chan fileResult, 1)
	go func() {
		fileStats := s.contentIO
		if s.debug != nil {
			fileStats = &contentReadStats{parent: s.contentIO}
		}
		started := time.Now()
		s.debug.event("open", path, 0, 0)
		var readTime, inspectTime time.Duration
		var result fileResult
		defer func() {
			s.debug.fileDone(path, fileStats, readTime, inspectTime, time.Since(started))
			done <- result
		}()
		f, err := os.Open(path)
		if err != nil {
			result = fileResult{err: err}
			return
		}
		opened.Store(f)
		defer f.Close()
		select {
		case <-cancel:
			return
		default:
		}
		readStart := time.Now()
		data, binary, err := s.readCachedContent(f, path, source, fileStats)
		readTime = time.Since(readStart)
		if binary {
			s.contentIO.binary.Add(1)
		}
		if err != nil {
			result = fileResult{err: err}
			return
		}
		select {
		case <-cancel:
			return
		default:
		}
		local := New(s.HomeDir, false)
		local.contentIO = s.contentIO
		local.reads = s.reads
		local.Deep = s.Deep
		local.debug = s.debug
		s.debug.event("inspect", path, fileStats.bytes.Load(), readTime)
		inspectStart := time.Now()
		if inspect != nil {
			inspect(local, data)
		}
		inspectTime = time.Since(inspectStart)
		result = fileResult{data: data, findings: local.Findings, stats: local.stats, scriptChecked: local.scriptChecked}
	}()
	select {
	case result := <-done:
		if time.Now().After(deadline) {
			s.recordStall(key, path)
			return nil
		}
		if result.err != nil {
			if optionalFileMissing(optional, result.err) {
				return nil
			}
			s.mu.Lock()
			s.stats.FilesUnreadable++
			s.mu.Unlock()
			s.scanError(path, result.err)
			return nil
		}
		return s.mergeFileResult(path, result)
	case <-timer.C:
		s.debug.event("timeout", path, 0, timeout)
		if f := opened.Load(); f != nil {
			go f.Close()
		}
		s.recordStall(key, path)
		return nil
	}
}

// Content accounting measures bytes returned by file reads, including rejected
// prefixes and failed reads. It excludes metadata, OS read-ahead and Git child I/O.
type contentReadStats struct {
	parent *contentReadStats
	bytes  atomic.Int64
	binary atomic.Int64
}
type measuredReader struct {
	reader io.Reader
	stats  *contentReadStats
}

func (r measuredReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for stats := r.stats; stats != nil; stats = stats.parent {
		stats.bytes.Add(int64(n))
	}
	return n, err
}

const SourceSniffBytes = 8 * 1024

// Read a prefix before allocating/reading the body of general-source candidates.
// This preserves whole-file inspection for text (including middle/tail markers).
// Selected metadata, lifecycle targets, exact hashes and persistence entrypoints
// deliberately retain their existing full-read policy.
func readScanContent(f *os.File, ext string, source bool, stats *contentReadStats, preserveNative ...bool) ([]byte, bool, error) {
	measured := measuredReader{f, stats}
	prefix := make([]byte, 32)
	n, err := io.ReadFull(measured, prefix)
	if failedPrefixRead(err) {
		return nil, false, err
	}
	prefix = prefix[:n]
	if nativeExecutableHeader(prefix) && !(len(preserveNative) > 0 && preserveNative[0]) {
		return prefix, true, nil
	}
	if assetExtension(ext) && validAsset(ext, prefix) {
		return prefix, false, nil
	}

	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.Size() >= SignatureScanMaxBytes {
		return nil, false, fileSizeError()
	}
	if source {
		var binary bool
		prefix, binary, err = sniffSourcePrefix(measured, prefix, ext)
		if err != nil || binary {
			return prefix, binary, err
		}
	}
	r := io.MultiReader(bytes.NewReader(prefix), measured)
	data, err := io.ReadAll(io.LimitReader(r, SignatureScanMaxBytes))
	if err == nil && len(data) >= SignatureScanMaxBytes {
		err = fileSizeError()
	}
	return data, false, err
}
func binarySourcePrefix(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			return false
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			return true
		}
		data = data[size:]
	}
	return false
}

func fileSizeError() error {
	return fmt.Errorf("%w: content must be below 100 MB (%d bytes); content was not checked", errFileTooLarge, SignatureScanMaxBytes)
}

// looksLikeText reports whether a buffer is plausibly text rather than a
// binary container. Used to distinguish "this .woff2 is JavaScript" from
// "this .woff2 is a font in a format we don't have a magic number for".
func looksLikeText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}

	printable := 0
	for _, b := range sample {
		if b == 0x00 {
			return false // NUL byte: binary
		}
		if b >= 0x20 && b < 0x7f {
			printable++
			continue
		}
		if b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return printable*100/len(sample) >= 95
}

// htmlPrefixes are the leading tokens of a document saved where a binary asset
// was expected.
var htmlPrefixes = []string{"<!doctype html", "<html", "<?xml", "<!--"}

// looksLikeHTML reports whether a buffer is an HTML or XML document.
//
// This exists to suppress a benign false-positive class rather than to detect
// anything: a site mirrored with `wget`, or a single-page app served behind a
// catch-all route, saves the index page under the requested asset's name when
// the asset 404s. The result is a `.otf` or `.woff2` on disk whose bytes are
// plainly not font data — true, and not an indicator of anything. The attack
// this check exists for hides JavaScript, not markup, so excluding documents
// costs no detection.
func looksLikeHTML(data []byte) bool {
	sample := data
	if len(sample) > 256 {
		sample = sample[:256]
	}
	lower := strings.ToLower(strings.TrimSpace(string(sample)))
	for _, p := range htmlPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// hasFontMagic reports whether a buffer starts with any known font container
// signature.
func hasFontMagic(data []byte) bool {
	for _, magic := range fontMagics {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return false
}

// checkSourceFile runs every content-based check against a single file found
// during the project walk. Called for non-directory entries only.
//
// Name-based checks run first and short-circuit: a file that is malicious by
// name alone never needs reading.
func (s *Scanner) checkSourceFile(path, name string) {
	if startupPath(path) {
		s.checkStartupFile(path, false)
		return
	}
	if extraToolchainPath(path) {
		s.checkApplicationFile(path)
		return
	}
	if name == "package.json" {
		s.checkPackageManifest(filepath.Dir(path), filepath.Base(filepath.Dir(path)), false)
		return
	}
	if s.persistenceChecked[path] || s.scriptChecked[path] {
		return
	}
	if persistenceEntrypointName(name) && discoveredPersistenceEntrypoint(path) {
		s.checkApplicationFile(path)
		return
	}
	if s.checkRepoArtifactName(path, name) {
		return
	}

	if name == ".gitignore" {
		s.checkGitignore(path)
		return
	}

	ext := strings.ToLower(filepath.Ext(name))
	isFont := slices.Contains(fontExtensions, ext)

	if !isFont && !shouldScanForSignatures(name) && !statSizeCandidate(path) {
		return
	}

	if s.processSourceFile(path, func(local *Scanner, data []byte) {
		local.inspectSourceContent(path, name, ext, isFont, data)
	}) != nil {
		s.stats.FilesChecked++
	}

}

// statSizeCandidate re-checks size for a file selected by an earlier rule whose
// extension is not otherwise eligible. One stat, only on that narrow path.
func statSizeCandidate(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && knownPayloadSize(info.Size())
}

// checkRepoPayloadHash confirms candidate artifacts without trusting the name,
// directory, or file size. Called inside the bounded content inspection.
func (s *Scanner) checkRepoPayloadHash(path, name string, data []byte) bool {
	size := int64(len(data))
	if !knownPayloadName(name) && !knownPayloadSize(size) {
		return false
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	for _, h := range KnownRepoPayloadHashes {
		sized := h.Size != 0 && h.Size == size
		if name != h.Filename && !sized {
			continue
		}
		if digest != h.SHA256 {
			continue
		}
		s.addFinding(Finding{
			Check:    "malicious-repo-artifact",
			Severity: SevCritical,
			Path:     path,
			Detail:   fmt.Sprintf("%s (attack: %s)%s", h.Desc, h.Attack, renamedNote(name, h)),
		})
		return true
	}
	return false
}

// renamedNote records that the bytes were identified without trusting the name.
func renamedNote(name string, h RepoPayloadHash) string {
	if name == h.Filename {
		return ""
	}
	return fmt.Sprintf("; identified by exact size and SHA-256, not by filename (published as %s)", h.Filename)
}

// checkRepoArtifactName reports whether a file is malicious by filename alone,
// adding a finding if so.
func (s *Scanner) checkRepoArtifactName(path, name string) bool {
	// Propagation artifacts are matched on basename alone — these filenames
	// have no legitimate use anywhere in a project tree.
	for _, a := range KnownRepoArtifacts {
		if name == a.Filename {
			s.stats.FilesChecked++
			s.addFinding(Finding{
				Check:    "malicious-repo-artifact",
				Severity: SevCritical,
				Path:     path,
				Detail:   fmt.Sprintf("%s (attack: %s)", a.Desc, a.Attack),
			})
			return true
		}
	}

	// `.inz.cjs` / `.inz.orig` are the sibling modules a patched Electron
	// entrypoint requires. Matched by suffix because the stem varies with
	// whichever file was patched.
	//
	// The community IR kit documents sidecar injection; ByteGuard corroborates
	// the backup suffix. Socket and StepSecurity's Joyfill reports independently
	// document the application targets and exact persistence markers. These
	// sources describe different builds of the same persistence mechanism.
	// https://socket.dev/blog/joyfill-npm-beta-releases-compromised
	// https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
	//
	// Known application entrypoint directories are also scanned separately,
	// including system installations outside $HOME and nested node_modules.
	// https://github.com/OsamaCodes62/nullreceiver-ir-kit (iocs/iocs.csv, scan_macos.sh)
	// Backup suffix: https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json
	if strings.HasSuffix(name, ".inz.cjs") || strings.HasSuffix(name, ".inz.orig") {
		s.stats.FilesChecked++
		s.addFinding(Finding{
			Check:    "malicious-repo-artifact",
			Severity: SevCritical,
			Path:     path,
			Detail:   "PolinRider implant module dropped beside a patched Electron or npm entrypoint (attack: polinrider (DPRK))",
		})
		return true
	}

	return false
}

// checkFakeFont reports a file named like a web font whose bytes are text.
// This holds regardless of which payload generation is inside, so it fires
// even when every string constant has rotated.
func (s *Scanner) checkFakeFont(path, ext string, data []byte) {
	if hasFontMagic(data) {
		return
	}
	data = trimAssetPadding(data)
	if hasFontMagic(data) || !looksLikeText(data) || looksLikeHTML(data) {
		return
	}
	s.addFinding(Finding{
		Check:    "fake-font-payload",
		Severity: SevCritical,
		Path:     path,
		Detail:   fmt.Sprintf("%s file contains text, not font data — JavaScript loader disguised as a web font (attack: polinrider (DPRK))", ext),
	})
}

// checkPayloadSignatures reports whether a known payload signature is present,
// adding a finding if so.
func (s *Scanner) checkPayloadSignatures(path string, data []byte) bool {
	if sig, ok := payloadSignature(data); ok {
		s.addFinding(Finding{
			Check:    "payload-signature",
			Severity: SevCritical,
			Path:     path,
			Detail:   fmt.Sprintf("%s (attack: %s)", sig.Desc, sig.Attack),
		})
		return true
	}
	return false
}

func payloadSignature(data []byte) (PayloadSignature, bool) {
	content := string(data)
	var lower string
	lowerReady := false
	caseInsensitiveContains := func(needle string) bool {
		if !lowerReady {
			lower = strings.ToLower(content)
			lowerReady = true
		}
		return strings.Contains(lower, strings.ToLower(needle))
	}
	for _, sig := range KnownPayloadSignatures {
		if sig.Requires != "" && !strings.Contains(content, sig.Requires) {
			continue
		}
		if strings.Contains(content, sig.Signature) ||
			(strings.HasPrefix(sig.Signature, "0xa322") && caseInsensitiveContains(sig.Signature)) ||
			(sig.Signature == "x-payload-b64" && caseInsensitiveContains(sig.Signature)) {
			return sig, true
		}
	}
	return PayloadSignature{}, false
}

// checkPadding warns on a file carrying the shape of an injection without a
// known signature: a run of padding long enough to push an appended payload
// off the right edge of an editor. Reported as a warning rather than a finding
// of fact, because the campaign rotates its constants and this is what a
// rotation past our signature list would look like.
//
// The text precondition is load-bearing, not a nicety. Pushing a payload off
// the right edge of an editor viewport is a trick that only means anything in
// a file a human reads as text; inside a binary container a run of 0x20 bytes
// is just data. A 21 MB CJK TrueType font has ample room to contain 200
// consecutive spaces in its glyph tables by coincidence, and flagging that is
// noise. Fonts that really are text still get caught — as a critical
// fake-font-payload finding, by the magic-number check above.
func (s *Scanner) checkPadding(path, ext string, isFont bool, data []byte) {
	if !isJSFamily(ext) && ext != ".dict" && !isFont {
		return
	}
	if !looksLikeText(data) {
		return
	}
	if !hasInlinePadding(data) {
		return
	}
	s.addFinding(Finding{
		Check:    "padded-source-file",
		Severity: SevWarn,
		Path:     path,
		Detail:   fmt.Sprintf("line contains %d+ spaces between text, which can hide appended code off-screen", ConfigPaddingRunLength),
	})
}

// Ignore leading indentation and trailing whitespace: the documented pattern
// separates existing source and appended content on the same line.
func hasInlinePadding(data []byte) bool {
	if !bytes.Contains(data, []byte(paddingRun)) {
		return false
	}
	for line := range bytes.Lines(data) {
		if bytes.Contains(bytes.TrimSpace(line), []byte(paddingRun)) {
			return true
		}
	}
	return false
}

// checkGitignore looks for entries an attack added to conceal a file it
// dropped. A .gitignore listing a file the developer never created is a
// deliberate concealment step, and it survives cleanup of the file itself.
func (s *Scanner) checkGitignore(path string) {
	if s.processFile(path, ReadTimeout, func(local *Scanner, data []byte) {
		for line := range strings.Lines(string(data)) {
			trimmed := strings.TrimSpace(line)
			for _, entry := range GitignoreInjectedLines {
				if trimmed == entry.Signature {
					local.addFinding(Finding{
						Check:    "gitignore-injection",
						Severity: SevCritical,
						Path:     path,
						Detail:   fmt.Sprintf("%s (attack: %s)", entry.Desc, entry.Attack),
					})
					return
				}
			}
		}
	}) != nil {
		s.stats.FilesChecked++
	}

}

// scanDirFiles runs content checks over the files directly inside one
// directory, without recursing. Used for project config directories
// (`.vscode`, `.claude`) that the walk stops descending into once it has
// matched them, so that `.vscode/tasks.json` is still inspected.
func (s *Scanner) scanDirFiles(dir string) {
	entries, err := s.readDir(dir)
	if err != nil {
		s.scanError(dir, err)
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if s.routineContentFile(path, e.Name(), e) {
			s.checkSourceFile(path, e.Name())
		}
	}
}

// checkNpmCLI looks for a global npm CLI entrypoint that has been overwritten.
// This is checked separately from the project walk because the global npm
// install lives outside the home directory on most platforms, and because it
// is the persistence that matters most: a patched cli.js re-spawns the malware
// on every npm invocation and survives a reboot, so a machine can be
// reinfected long after every poisoned repo has been cleaned.
func (s *Scanner) checkNpmCLI() {
	seen := make(map[string]bool)

	for _, pattern := range NpmCLIGlobs(s.HomeDir) {
		for _, dir := range s.persistenceDirs(filepath.Dir(pattern)) {
			path := filepath.Join(dir, filepath.Base(pattern))
			if seen[path] {
				continue
			}
			seen[path] = true
			s.checkPersistenceSiblings(dir)

			info, err := os.Stat(path)
			if err != nil {
				s.persistenceError(path, err)
				continue
			}
			if !info.Mode().IsRegular() {
				s.persistenceError(path, fmt.Errorf("expected a regular npm entrypoint file"))
				continue
			}
			s.markPersistenceChecked(path)
			s.stats.FilesChecked++
			s.log("checking npm CLI entrypoint: %s (%d bytes)", path, info.Size())

			if info.Size() > NpmCLIMaxNormalBytes {
				s.addFinding(Finding{
					Check:    "patched-npm-cli",
					Severity: SevCritical,
					Path:     path,
					Detail: fmt.Sprintf(
						"global npm CLI entrypoint is %d bytes (a genuine cli.js is under 1 KB) — overwritten to re-spawn a payload on every npm/npx/npm exec call (attack: polinrider (DPRK))",
						info.Size(),
					),
				})
				continue
			}

			// Under the size threshold, still read it: a smaller loader stub
			// carrying a known signature is just as bad.
			s.processFile(path, ReadTimeout, func(local *Scanner, data []byte) {
				if sig, ok := persistenceSignature(data); ok {
					local.addFinding(Finding{
						Check:    "patched-npm-cli",
						Severity: SevCritical,
						Path:     path,
						Detail:   fmt.Sprintf("global npm CLI entrypoint carries an injected payload — %s (attack: %s)", sig.Desc, sig.Attack),
					})
				}
			})
		}
	}
}

func hasIncomplete(findings []Finding) bool {
	for _, f := range findings {
		if f.Check == "scan-incomplete" {
			return true
		}
	}
	return false
}

// Source-signature checks do not analyze native executable code. Recognize
// native headers before the text size limit; a script renamed .node still scans.
func nativeExecutableHeader(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	if bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return (data[4] == 1 || data[4] == 2) && (data[5] == 1 || data[5] == 2) && data[6] == 1
	}
	for _, magic := range [][]byte{{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}, {0xfe, 0xed, 0xfa, 0xcf}, {0xfe, 0xed, 0xfa, 0xce}, {0xca, 0xfe, 0xba, 0xbe}, {0xbe, 0xba, 0xfe, 0xca}} {
		if bytes.Equal(data[:4], magic) {
			return true
		}
	}
	return false
}

func (s *Scanner) inspectSourceContent(path, name, ext string, isFont bool, data []byte) {
	if name == "tasks.json" && filepath.Base(filepath.Dir(path)) == ".vscode" {
		s.checkFontTask(path, data)
	}

	if isFont {
		s.checkFakeFont(path, ext, data)
	}

	if !isFont {
		s.checkDisguisedAsset(path, ext, data)
	}
	if assetExtension(ext) && validAsset(ext, data) {
		return
	}
	if s.checkRepoPayloadHash(path, name, data) {
		return
	}
	s.inspectGeneralContent(path, data)
	matched := false
	for _, f := range s.Findings {
		if f.Check == "payload-signature" {
			matched = true
		}
	}
	if !matched {
		s.checkPadding(path, ext, isFont, data)
	}
}

func (s *Scanner) mergeFileResult(path string, result fileResult) []byte {
	if s.scriptChecked == nil {
		s.scriptChecked = make(map[string]bool)
	}
	for path := range result.scriptChecked {
		s.scriptChecked[path] = true
	}
	s.stats.PackagesScanned += result.stats.PackagesScanned
	s.stats.ComposerPackagesScanned += result.stats.ComposerPackagesScanned
	s.stats.FilesChecked += result.stats.FilesChecked
	s.stats.FilesUnreadable += result.stats.FilesUnreadable
	for _, finding := range result.findings {
		s.addFinding(finding)
	}
	if hasIncomplete(result.findings) {
		if result.stats.FilesUnreadable == 0 {
			s.stats.FilesUnreadable++
		}
		return nil
	}
	s.stats.ContentBytesRead = s.contentIO.bytes.Load()
	s.stats.BinaryPrefixesSkipped = s.contentIO.binary.Load()
	if s.Verbose && s.stats.ContentBytesRead >= s.nextReadReport+(1<<30) {
		s.nextReadReport = s.stats.ContentBytesRead
		s.log("content reads: %.2f GiB so far; current file: %s", float64(s.stats.ContentBytesRead)/(1<<30), path)
	}
	return result.data
}

func sniffSourcePrefix(measured measuredReader, prefix []byte, ext string) ([]byte, bool, error) {
	rest := make([]byte, SourceSniffBytes-len(prefix))
	n, err := io.ReadFull(measured, rest)
	if failedPrefixRead(err) {
		return nil, false, err
	}
	prefix = append(prefix, rest[:n]...)
	sample := prefix
	if assetExtension(ext) {
		sample = trimAssetPadding(sample)
	}
	// A partial UTF-8 rune at the sniff boundary is not binary. All-padding
	// assets also remain candidates: script text can occur after the padding.
	return prefix, binarySourcePrefix(sample), nil
}

func optionalFileMissing(optional bool, err error) bool { return optional && os.IsNotExist(err) }
func failedPrefixRead(err error) bool {
	return err != nil && err != io.EOF && err != io.ErrUnexpectedEOF
}
