package scan

import (
	"bytes"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// GitObjectPathsVersion is the first release whose rev-list can emit object
// paths in a machine-parsable framing. Without it the only safe option is
// --no-object-names: the legacy format joins the object ID and the path with
// a space on one newline-terminated line, and a path may contain either, so
// nothing downstream can tell a long path from two records. NUL framing
// removes the ambiguity rather than guessing around it, which is why the
// path-gated half of the history scan is gated on this version instead of
// parsing the legacy form heuristically.
//
// It is deliberately not the scanner's minimum. Every other Git command here
// works at 2.45, so an older Git still gets the size-matched history scan it
// gets today; only the path-gated checks are withheld, and their absence is
// reported as scope rather than passed off as coverage.
// https://github.com/git/git/blob/master/Documentation/RelNotes/2.50.0.adoc
var GitObjectPathsVersion = [2]int{2, 50}

func gitPathsSupported(version string) bool {
	v, ok := parseGitVersion(version)
	if !ok {
		return false
	}
	return v[0] > GitObjectPathsVersion[0] ||
		(v[0] == GitObjectPathsVersion[0] && v[1] >= GitObjectPathsVersion[1])
}

// gitContentCandidate decides whether a history blob is worth a body read.
//
// It mirrors the filesystem selection rule (targetedContentFile and
// injectionContentFile), not the broader shouldScanForSignatures eligibility
// test. The distinction is the whole ballgame: selecting by source extension
// reads every .py, .js and .json ever committed, which on a real machine
// meant reading a developer's own IOC research scripts out of history and
// reporting their C2 constants as indicators. A source extension never alone
// selects a file for reading on disk, and history is not an exception.
//
// Only the name-derived rules carry over. The filesystem versions also consult
// the tree around the file -- whether a directory was recognised as a project,
// whether a persistence entrypoint was discovered there -- and a historical
// path has no such tree to consult.
//
// Size-matched blobs are handled separately by the caller and need no name, so
// a renamed dropper is still reachable here exactly as it is on disk.
func gitContentCandidate(path, name string) bool {
	if name == "" {
		return false
	}
	if name == ".gitignore" || knownPayloadName(name) {
		return true
	}
	if slices.ContainsFunc(KnownRepoArtifacts, func(a ProjectArtifact) bool { return a.Filename == name }) {
		return true
	}
	if strings.HasSuffix(name, ".inz.cjs") || strings.HasSuffix(name, ".inz.orig") {
		return true
	}
	if slices.Contains(injectableSourceNames, name) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	if strings.Contains(name, ".config.") && isJSFamily(ext) {
		return true
	}
	if slices.Contains(fontExtensions, ext) {
		return true
	}
	dir := path[:max(strings.LastIndexByte(path, '/')+1, 0)]
	dir = strings.TrimSuffix(dir, "/")
	if i := strings.LastIndexByte(dir, '/'); i >= 0 {
		dir = dir[i+1:]
	}
	return (dir == ".vscode" || dir == ".claude") && name == "settings.json"
}

// inspectGitBlob runs the identity-based content checks against a blob body.
//
// Deliberately not the full filesystem inspection. The general heuristics --
// loader structure, escaped execution, Unicode concealment -- earn their
// warnings on a working tree, where each file appears once and the reader can
// act on what they find. History holds every revision of every file, so one
// pattern in one file becomes a warning per revision, and the finding points
// at a commit nobody is going to edit. Measured on a 49,000-blob repository,
// the heuristics produced 305 warnings and no indicator.
//
// What survives the move is everything that names a specific published
// payload: an artifact filename, an injected .gitignore line, an exact
// payload hash, a signature string, and the carved config-append span. Those
// stay true regardless of how many revisions carry them.
//
// The checks are handed the historical path joined onto the repository so the
// directory-sensitive ones still work -- a tasks.json is only a VS Code task
// file when its parent is .vscode. That joined path does not necessarily name
// a file that exists, so every finding is rewritten before it is merged: the
// reported path becomes the repository, and the detail carries the historical
// path, the blob ID and the command that locates the commits touching it.
func (s *Scanner) inspectGitBlob(repo, path, id string, data []byte) {
	name := filepath.Base(path)
	local := New(s.HomeDir, false)
	local.debug = s.debug
	local.inspectGitBlobContent(filepath.Join(repo, filepath.FromSlash(path)), name, data)
	for _, f := range local.Findings {
		if f.Check == "scan-incomplete" || f.Check == "scan-limited" {
			continue
		}
		s.recordGitHistoryHit(f, path, id)
	}
}

// recordGitHistoryHit accumulates instead of reporting, because history
// repeats itself: a config poisoned once is a separate blob in every later
// revision that kept it, and a file's whole edit history is in reach. On a
// real machine one indicator in one file came back 48 times. One line per
// indicator per repository, with the revision count, says the same thing.
func (s *Scanner) recordGitHistoryHit(f Finding, path, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gitHistory == nil {
		s.gitHistory = make(map[string]*gitHistoryHit)
	}
	key := f.Check + "\x00" + f.Detail
	if hit, ok := s.gitHistory[key]; ok {
		hit.revisions++
		return
	}
	s.gitHistory[key] = &gitHistoryHit{order: len(s.gitHistory), finding: f, path: path, id: id, revisions: 1}
}

// flushGitHistory emits one finding per indicator for the repository just
// scanned, naming the first blob seen as the one to investigate.
func (s *Scanner) flushGitHistory(repo string) {
	s.mu.Lock()
	hits := make([]*gitHistoryHit, 0, len(s.gitHistory))
	for _, hit := range s.gitHistory {
		hits = append(hits, hit)
	}
	s.gitHistory = nil
	s.mu.Unlock()
	slices.SortFunc(hits, func(a, b *gitHistoryHit) int { return a.order - b.order })
	for _, hit := range hits {
		others := ""
		if hit.revisions > 1 {
			others = fmt.Sprintf(", and in %d further blob(s) here", hit.revisions-1)
		}
		f := hit.finding
		f.Path = repo
		// cause is what every repository carrying this indicator shares, so
		// the report prints it once; evidence is the blob only this one has.
		f.cause = strings.TrimSuffix(f.Detail, ".") + "; found in Git history. May be historical, not in the checkout."
		f.evidence = fmt.Sprintf("%s, blob %s%s — git log --all --find-object=%s", hit.path, hit.id, others, hit.id)
		f.Detail = f.cause + " " + f.evidence
		s.addFinding(f)
	}
}

type gitHistoryHit struct {
	order     int
	finding   Finding
	path, id  string
	revisions int
}

func (s *Scanner) inspectGitBlobContent(display, name string, data []byte) {
	if s.checkRepoArtifactName(display, name) {
		// Matched on basename alone; the body adds nothing.
		return
	}
	if name == ".gitignore" {
		s.inspectGitignore(display, data)
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	if slices.Contains(fontExtensions, ext) {
		s.checkFakeFont(display, ext, data)
	}
	if name == "tasks.json" && filepath.Base(filepath.Dir(display)) == ".vscode" {
		s.checkFontTask(display, data)
	}
	if s.checkRepoPayloadHash(display, name, data) {
		return
	}
	if s.checkGitBlobSignature(display, data) {
		return
	}
	// The config-append landing has no fixed file hash -- the carrier is the
	// victim's own build config -- so the span is carved and hashed instead.
	// Unlike the filesystem path, a padded line that matches no published
	// span is not reported: minified sources carry long space runs, and in
	// history that warning would repeat for every revision of every bundle.
	if isJSFamily(ext) || ext == ".dict" {
		if looksLikeText(data) && hasInlinePadding(data) {
			s.checkPaddedSegmentHash(display, data)
		}
	}
}

// checkGitBlobSignature is the exact-signature half of inspectGeneralContent,
// without the heuristics that follow it there.
func (s *Scanner) checkGitBlobSignature(display string, data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return false
	}
	sig, ok := payloadSignature(normalizeASCII(data))
	if !ok {
		return false
	}
	severity := SevCritical
	detail := fmt.Sprintf("%s (attack: %s)", sig.Desc, sig.Attack)
	if researchText(display) {
		severity = SevWarn
		detail += "; documentation/test context: may be an inert example, not evidence of execution"
	}
	s.addFinding(Finding{Check: "payload-signature", Severity: severity, Path: display, Detail: detail})
	return true
}

// addGitPayloadFinding keeps the hash matches on the same cause/evidence split
// as the rest of the history checks, so two repositories carrying one payload
// share its explanation instead of printing it twice.
func (s *Scanner) addGitPayloadFinding(repo, id, cause, evidence string) {
	evidence += " — git log --all --find-object=" + id
	s.addFinding(Finding{
		Check:    "git-payload-hash",
		Severity: SevCritical,
		Path:     repo,
		cause:    cause,
		evidence: evidence,
		Detail:   cause + " " + evidence,
	})
}
