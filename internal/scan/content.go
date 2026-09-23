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
// `api_manager.js` and `generate.js` are observed August-wave carriers: that
// wave appended its payload to the last line of whatever file the project
// already loaded, so the carrier is an ordinary source file rather than a
// config. Incident-observed names, not a published IOC list.
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
	"api_manager.js",
	"generate.js",
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
// Cloud-sync placeholders are recognised by their filesystem flag and skipped
// before they are opened, so the common cause of a hang never reaches here.
// What remains is a mount or a disk that has stopped answering, where a read
// blocks indefinitely and then fails. Four MiB from a local disk is effectively
// instant, so this only ever fires on something genuinely stuck.
const ReadTimeout = 5 * time.Second

// StallBudget is the total wall-clock time one scan may lose to reads that
// never returned before it gives up and reports what it has.
//
// ReadTimeout bounds each individual file but not the run. Cloud placeholders
// are recognised and skipped without being opened, so a read that hangs now
// means something is actually broken -- a wedged NFS or SMB mount, a dying
// disk, a FUSE filesystem whose daemon died -- and in that situation there is
// no healthy subtree worth salvaging by guessing at which directory is at
// fault. Twelve timeouts is enough to tell one odd file from a machine that
// cannot answer, and it makes the worst case a number this file can state:
// a scan never loses more than a minute to hangs, whatever the layout.
const StallBudget = 60 * time.Second

// stallBudgetSpent reports whether the scan has already given up on reading.
func (s *Scanner) stallBudgetSpent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readsAbandoned
}

// recordTimeout books the time one read spent hanging. Each timed-out file is
// its own warning -- it is named, so the reader knows exactly what was missed
// and can go look. Spending the whole budget is different in kind: everything
// after it goes unread and nothing names it, so that is the critical one.
func (s *Scanner) recordTimeout(path string) {
	s.mu.Lock()
	s.stats.FilesUnreadable++
	s.timeLostToStalls += ReadTimeout
	trip := !s.readsAbandoned && s.timeLostToStalls >= StallBudget
	if trip {
		s.readsAbandoned = true
	}
	s.mu.Unlock()

	s.log("file processing timed out after %s, not fully scanned: %s", ReadTimeout, path)

	s.addFinding(Finding{
		Check:            "scan-incomplete",
		coverageCategory: "timed out",
		Severity:         SevWarn,
		Path:             path,
		Detail: fmt.Sprintf(
			"Reading or inspecting this file did not finish within %s, so its contents were not scanned. "+
				"Usually a stalled network mount or a cloud-sync file the provider never delivered. "+
				"Bring it online and re-run to cover it.", ReadTimeout),
	})

	if trip {
		s.addFinding(Finding{
			Check:            "scan-incomplete",
			coverageCategory: "timed out",
			Severity:         SevCritical,
			Path:             "content",
			Detail:           abandonDetail(0),
		})
	}
}

// abandonDetail explains a scan that ran out of patience. How much went unread
// is only known once the walk is over, so recordTimeout emits this with zero
// and finalizeStalls rewrites it with the real count: one finding standing for
// an unbounded remainder gives a reader nothing to weigh it by.
func abandonDetail(skipped int) string {
	unread := ""
	if skipped > 0 {
		unread = fmt.Sprintf("%d further file(s) went unread. ", skipped)
	}
	return fmt.Sprintf(
		"This scan spent its whole %s budget on reads that never returned, so it stopped reading files and gave up. %s"+
			"The individual timeouts above name what hung. Something on this machine is not answering -- a stalled network mount, "+
			"a failing disk, or a sync client that is running but not serving. Fix it and re-run: these results cannot be trusted as a clean scan.",
		StallBudget, unread)
}

// recordDataless reports a file whose bytes are not on local disk. Reading one
// asks the sync provider to fetch it, which is exactly the hang the budget
// above exists to survive -- and on a healthy machine it would also mean a scan
// silently downloading gigabytes of someone's archived files. Skipping it loses
// coverage of one named file, which is a warning, not a failed scan.
func (s *Scanner) recordDataless(path string) {
	s.mu.Lock()
	s.stats.FilesUnreadable++
	s.mu.Unlock()
	s.debug.event("skip-dataless", path, 0, 0)
	s.addFinding(Finding{
		Check:            "scan-incomplete",
		coverageCategory: "not downloaded",
		Severity:         SevWarn,
		Path:             path,
		Detail: "This file is a cloud-sync placeholder: its contents are not on local disk, and reading it would ask the provider to download it. " +
			"It was not scanned. Make it available offline and re-run to cover it.",
	})
}

// finalizeStalls folds the count of reads skipped after the budget ran out into
// the finding that announced it, once the walk that skipped them has finished.
func (s *Scanner) finalizeStalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readsSkipped == 0 {
		return
	}
	for i, f := range s.Findings {
		if f.Check == "scan-incomplete" && f.Severity == SevCritical && f.Path == "content" {
			s.Findings[i].Detail = abandonDetail(s.readsSkipped)
		}
	}
}

// readCapped is the read-only form of the same per-file processing deadline.
func (s *Scanner) readCapped(path string) []byte {
	return s.processFile(path, ReadTimeout, nil)
}

// statFile resolves a path before it is opened. Tests replace it so a FIFO
// still reaches the read and exercises the timeout path.
var statFile = os.Stat

// isDataless reports a cloud placeholder from the stat the read already did.
// Tests replace it: no portable way exists to create one on demand.
var isDataless = datalessFile

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

// inheritedScopeRoots is the scope a per-read Scanner copy must carry, resolved
// here on the parent so a read that outlives its deadline cannot leave a
// goroutine filling the cache beside the caller. Nil when the scan is unconfined.
func (s *Scanner) inheritedScopeRoots() []string {
	if !s.Only {
		return nil
	}
	return s.scopeRootList()
}

// openForRead screens a selected path and opens it. A nil file with a nil error
// means the path was deliberately not read and is not a coverage failure here.
//
// Stat before opening, not after: opening a FIFO blocks until a writer appears,
// so a named pipe anywhere in a scanned tree would cost a full ReadTimeout.
// Nothing but a regular file has content to inspect, and a placeholder whose
// bytes are not on local disk must not be opened at all, because reading one
// asks the sync provider to fetch it. statFile is indirected for tests, which
// need a FIFO to stay readable to simulate an unresponsive mount.
func (s *Scanner) openForRead(path string) (*os.File, error) {
	info, err := statFile(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		s.debug.event("skip-irregular", path, 0, 0)
		return nil, nil
	}
	if isDataless(info) {
		s.recordDataless(path)
		return nil, nil
	}
	return os.Open(path)
}

func (s *Scanner) processFilePolicy(path string, timeout time.Duration, inspect func(*Scanner, []byte), optional, source bool) []byte {
	s.debug.selection(path)
	if s.stallBudgetSpent() {
		s.mu.Lock()
		s.stats.FilesUnreadable++
		s.readsSkipped++
		s.mu.Unlock()
		return nil
	}
	scopeRoots := s.inheritedScopeRoots()
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
		f, err := s.openForRead(path)
		if err != nil {
			result = fileResult{err: err}
			return
		}
		if f == nil {
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
		// Carry the scope with it. Inspection callbacks reach paths named by
		// file content (a lifecycle target may be "../../outside.js"), and
		// they check them against this copy, not against s.
		local.Only = s.Only
		local.ExtraRoots = s.ExtraRoots
		local.scopeRoots = scopeRoots
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
		return s.finishFileResult(path, result, optional)
	case <-timer.C:
		// The read may have landed in the same instant the timer fired; select
		// chooses at random between two ready cases. A finished read is a
		// finished read, and its findings cost a full timeout to produce, so
		// take the result rather than discarding it and blaming the volume.
		select {
		case result := <-done:
			return s.finishFileResult(path, result, optional)
		default:
		}
		s.debug.event("timeout", path, 0, timeout)
		if f := opened.Load(); f != nil {
			go f.Close()
		}
		s.recordTimeout(path)
		return nil
	}
}

// finishFileResult records a completed read, whether it finished inside the
// deadline or at the edge of it. Completion is what matters: the bytes were
// read and inspected, so the findings are as good as any other file's.
func (s *Scanner) finishFileResult(path string, result fileResult, optional bool) []byte {
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
	// An entry with no published filename lands in whatever file the project
	// already loads, so there is no name to compare against.
	if h.Filename == "" {
		return "; identified by exact size and SHA-256, not by filename"
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

// Matching is done over the bytes rather than a string copy of them: this
// runs once per blob across a repository's whole history, where the copy
// alone came to hundreds of megabytes on a large repository.
func payloadSignature(data []byte) (PayloadSignature, bool) {
	var lower []byte
	lowerReady := false
	caseInsensitiveContains := func(needle string) bool {
		if !lowerReady {
			lower = bytes.ToLower(data)
			lowerReady = true
		}
		return bytes.Contains(lower, []byte(strings.ToLower(needle)))
	}
	contains := func(needle string) bool { return bytes.Contains(data, []byte(needle)) }
	for _, sig := range KnownPayloadSignatures {
		if sig.Requires != "" && !contains(sig.Requires) {
			continue
		}
		if contains(sig.Signature) ||
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
	if s.checkPaddedSegmentHash(path, data) {
		return
	}
	s.addFinding(Finding{
		Check:    "padded-source-file",
		Severity: SevWarn,
		Path:     path,
		Detail:   fmt.Sprintf("line contains %d+ spaces between text, which can hide appended code off-screen", ConfigPaddingRunLength),
	})
}

// checkPaddedSegmentHash carves the appended span out of a padded line and
// hashes it. The published hashes for the config-append variant are hashes of
// a span inside a carrier, not of a file: the carrier is the victim's own
// build config, so its file hash is whatever their config happens to be and
// matches nothing. Only the injected span is constant across victims.
//
// Two spans are carved per padded line, because the injector's whitespace run
// is itself part of the published invariant: the payload alone, and the
// payload behind its padding. Both are compared against the sized entries.
// Carving is pure slicing over bytes already read; nothing is executed.
func (s *Scanner) checkPaddedSegmentHash(path string, data []byte) bool {
	h, n, ok := paddedPayloadHash(data)
	if !ok {
		return false
	}
	s.addFinding(Finding{
		Check:    "payload-signature",
		Severity: SevCritical,
		Path:     path,
		Detail: fmt.Sprintf("%s (attack: %s); matched as a %d-byte span appended to this file behind a whitespace run, not as the file's own hash",
			h.Desc, h.Attack, n),
	})
	return true
}

// paddedPayloadHash returns the sized entry a carved span matches, and the
// span's length.
func paddedPayloadHash(data []byte) (RepoPayloadHash, int, bool) {
	for line := range bytes.Lines(data) {
		idx := bytes.Index(line, []byte(paddingRun))
		if idx < 0 {
			continue
		}
		// Span the full whitespace run, however much longer than the
		// threshold it is, so the padded form is carved at its real length.
		start := idx
		for start > 0 && line[start-1] == ' ' {
			start--
		}
		end := idx + len(paddingRun)
		for end < len(line) && line[end] == ' ' {
			end++
		}
		payload := bytes.TrimRight(line[end:], "\r\n")
		if len(payload) == 0 {
			continue
		}
		padded := bytes.TrimRight(line[start:], "\r\n")
		for _, span := range [][]byte{payload, padded} {
			if h, ok := sizedPayloadHash(span); ok {
				return h, len(span), true
			}
		}
	}
	return RepoPayloadHash{}, 0, false
}

// sizedPayloadHash compares one carved span against the sized entries. Size
// is checked before hashing so an ordinary long line costs no SHA-256.
func sizedPayloadHash(span []byte) (RepoPayloadHash, bool) {
	for _, h := range KnownRepoPayloadHashes {
		if h.Size == 0 || h.Size != int64(len(span)) || h.SHA256 == "" {
			continue
		}
		if fmt.Sprintf("%x", sha256.Sum256(span)) == h.SHA256 {
			return h, true
		}
	}
	return RepoPayloadHash{}, false
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
		local.inspectGitignore(path, data)
	}) != nil {
		s.stats.FilesChecked++
	}

}

// inspectGitignore is the content half of checkGitignore, split out so the
// same whole-line comparison can run against a Git blob body, which arrives
// as bytes off a pipe rather than from a file on disk.
func (s *Scanner) inspectGitignore(path string, data []byte) {
	for line := range strings.Lines(string(data)) {
		trimmed := strings.TrimSpace(line)
		for _, entry := range GitignoreInjectedLines {
			if trimmed == entry.Signature {
				s.addFinding(Finding{
					Check:    "gitignore-injection",
					Severity: SevCritical,
					Path:     path,
					Detail:   fmt.Sprintf("%s (attack: %s)", entry.Desc, entry.Attack),
				})
				return
			}
		}
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
			if seen[path] || !s.pathInScope(dir) {
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
