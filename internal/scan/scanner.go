package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Severity represents finding severity.
type Severity int

const (
	SevInfo Severity = iota
	SevWarn
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevWarn:
		return "WARN"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding represents a single scan result.
type Finding struct {
	coverageCategory string
	// rollup collapses a check that routinely fires across dozens of packages
	// into one human-report block labelled by subject instead of one block and
	// one path list per subject. JSON and the saved report keep every record.
	rollup string
	// cause is the shared explanation behind a finding whose Detail also
	// carries evidence unique to one location -- a Git blob ID, a historical
	// path. Grouping on the whole Detail would print the same explanation once
	// per location; grouping on cause prints it once and hangs the evidence
	// off each path. Empty for the ordinary case where Detail is the cause.
	cause    string
	evidence string
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Detail   string   `json:"detail"`
}

// ArtifactCheck describes a known malicious file to look for.
type ArtifactCheck struct {
	Path     string
	Absolute bool
	Desc     string
	Attack   string
}

// Scanner orchestrates all checks.
type Scanner struct {
	HomeDir  string
	Findings []Finding
	mu       sync.Mutex
	Verbose  bool
	// Deep adds declared dependency entrypoint and known-candidate inspection.
	// Metadata, lifecycle targets and targeted persistence run in both modes.

	Deep         bool
	Git          bool
	NpmCache     bool
	Broad        bool
	BrowserCache bool
	// Resolve opts into looking up the known C2 domains at scan time. Off by
	// default: the query goes to nameservers the campaign may still control,
	// and a dead domain reparked on shared hosting resolves to an address the
	// machine legitimately talks to, which would report as a critical.
	Resolve         bool
	contentDirs     map[string]bool
	gitHistory      map[string]*gitHistoryHit
	dependencyDirs  map[string]bool
	rawCacheSkipped map[string]bool
	linkNotices     map[string]bool
	stats           ScanStats
	// timeLostToStalls accumulates the wall-clock time this scan has spent on
	// reads that never returned. Once it reaches StallBudget the scan stops
	// reading files entirely: readsAbandoned latches true and readsSkipped
	// counts what went unread afterwards, so the finding can say how much was
	// lost instead of standing for an unbounded remainder. Guarded by mu.
	timeLostToStalls time.Duration
	readsAbandoned   bool
	readsSkipped     int
	// Explicit persistence checks bypass dependency boundaries; avoid reporting
	// those same files again in the home walk.
	persistenceChecked map[string]bool
	ExtraRoots         []string
	// TempRoots are the temp directories to walk, normally DefaultTempRoots().
	TempRoots []string
	// SkipTempRoots drops those directories from the walk, for a run that
	// does not want its report dominated by build and installer debris. The
	// staging names are still checked at the top of each temp directory
	// (checkSkippedTempTops), so temp directories are traversed no longer
	// rather than unscanned, and the run says so with a scope notice.
	SkipTempRoots bool
	// tempRoots caches the resolved temp directories this run covers, and
	// tempSpellings every path prefix they can be reached under.
	tempRoots     []string
	tempSpellings []string
	// scopeRoots caches the resolved roots pathInScope compares against.
	scopeRoots []string
	// phaseNum counts the progress lines printed so far.
	phaseNum int
	// Only restricts the run to the roots the user named: the machine-wide
	// phases (fixed artifact paths, persistence roots, system Python paths,
	// live connections) are skipped entirely, because none of them is anchored in the
	// requested directory. Intended for one-off checks of a single tree and
	// for rapid iteration on fixtures, where a full home walk is the cost.
	Only bool
	// Invocation labels the run with the build version and the flags it was
	// given. Printed when the scan starts as well as in the final summary, so
	// a captured log says what produced it without reading to the end.
	Invocation        string
	persistenceWalked map[string]bool
	packageChecked    map[string]bool
	scriptChecked     map[string]bool
	contentIO         *contentReadStats
	nextReadReport    int64
	debug             *scanDebug
	discovery         *scanDiscovery
	reads             *contentCache
}

// ScanStats tracks scan progress.
type ScanStats struct {
	Debug *DebugReport `json:"debug,omitempty"`
	Git   bool
	// GitPath and GitVersion are recorded on every Git-enabled run, whether
	// it worked or not. Without them the reason a fleet machine scanned no
	// repositories is only inferable from an error string, and only by
	// someone who reads the coverage rows.
	GitPath                string
	GitVersion             string
	GitRepositoriesFound   int
	GitRepositoriesScanned int
	GitBlobsChecked        int
	GitBlobsConsidered     int
	GitBlobsIdentified     int
	GitBlobsInspected      int
	GitCacheMarkersSkipped int
	// GitSkipped records that the Git phase never ran because the scan had
	// already spent its stall budget, so zero repositories is not scope.
	GitSkipped              bool
	NodeModulesFound        int
	PackagesScanned         int
	SitePackagesFound       int
	PythonPackagesScanned   int
	ComposerVendorsFound    int
	ComposerPackagesScanned int
	FilesChecked            int
	ContentBytesRead        int64
	BinaryPrefixesSkipped   int64
	// FilesUnreadable counts files selected for content scanning whose read
	// failed or timed out — a cloud placeholder the provider could not materialize, a
	// stalled network mount, or similar. Counted, not swallowed: a scan that
	// gave up on a whole synced folder must not read as a clean one.
	FilesUnreadable int
	// Deep records whether the scan read inside dependency directories. Kept
	// in stats so output can state it plainly: a fast scan that found nothing
	// must not be reported the same way as a deep one that found nothing.
	Deep bool
	// HomeRoot is the home directory when the run actually walked it, so the
	// zero-repository notice can expand `~` to a real path. Empty under -only,
	// where home is not a scan root and naming it would mislead.
	HomeRoot string
	Duration time.Duration
}

// New creates a scanner targeting the given home directory.
func New(homeDir string, verbose bool) *Scanner {
	return &Scanner{
		HomeDir:   homeDir,
		Verbose:   verbose,
		contentIO: new(contentReadStats),
		reads:     newContentCache(),
	}
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, previous := range s.Findings {
		if previous.Check == f.Check && previous.Path == f.Path && previous.Detail == f.Detail && previous.Severity == f.Severity {
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

func (s *Scanner) log(format string, args ...any) {
	s.progress("  [scan] "+format+"\n", args...)
}

// printRunHeader states what this run is before it produces any finding: the
// same version-and-flags label the final summary ends with, then the scope it
// was pointed at. A captured log then says what produced it from its first
// line, not only its last.
func (s *Scanner) printRunHeader() {
	if s.Invocation != "" {
		s.progress("%s\n", s.Invocation)
	}
	// Every directory this run walks on one line. Naming only the home
	// directory understated the scope: requested roots and the temp
	// directories are walked the same way and belong in the same list.
	label := "Scanning directories"
	if s.Only {
		label = "Scanning only"
	}
	dirs := append([]string{s.HomeDir}, s.ExtraRoots...)
	dirs = append(dirs, s.tempWalkRoots()...)
	s.progress("%s: %s\n", label, quotedPathList(dirs))
	// These roots are walked for persistence on every run without being asked
	// for, so a header that named only the home directory understated the
	// scope. Absent roots are skipped by the walk and so go unlisted here.
	if present := existingPersistenceRoots(); !s.Only && len(present) > 0 {
		s.progress("Persistence-only roots: %s\n", quotedPathList(present))
	}
	s.progress("Platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)
	// The one statement that changes what the phase lines below mean, so it
	// gets its own paragraph instead of a clause among the scope lines.
	if s.Only {
		s.progress("ONLY MODE: nothing outside the given root(s) is read, and active network connections and running processes are not scanned!\n\n")
	}
}

// phase numbers the progress lines as they print. -only never takes the
// process or connection snapshot, so that run counts two phases fewer rather
// than printing ones the reader would have to discount.
func (s *Scanner) phase(label string) {
	total := 3 // artifacts, directories, python
	if !s.Only {
		total += 2 // the process and connection snapshots
	}
	if s.Git {
		total++
	}
	s.phaseNum++
	s.progress("[%d/%d] %s...\n", s.phaseNum, total, label)
}

// Run executes all checks and returns findings.
func (s *Scanner) Run() ([]Finding, ScanStats) {
	start := time.Now()
	defer s.debug.summary()

	s.printRunHeader()

	// Phase 1: Check known malicious artifacts (fast, fixed paths) and the
	// global npm CLI entrypoint, which lives outside the home directory.
	// Under -only each candidate is filtered by pathInScope, so the
	// home-anchored half — which resolves inside the requested root — still
	// runs and the machine-anchored half does not. The header states the
	// scope, so the phase line reads the same either way.
	s.phase("Scanning known malicious artifact paths")
	s.debug.stage("artifacts/persistence")
	s.checkArtifacts()
	s.checkNpmCLI()
	s.checkApplicationPersistence()
	s.checkPersistenceRoots()
	s.checkRuntimeStaging()
	s.checkExtraToolchains()
	s.checkStartupFiles()

	// Phase 2: Walk home for node_modules and project-local payload artifacts.
	// What gets selected for reading is already stated by the scope notice
	// below, so the phase line names the directories and stops there.
	s.phase("Scanning project directories (node_modules, vendor, .claude, .vscode)")
	s.debug.stage("projects")
	if !s.Broad {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: "content", Detail: "Ordinary content reads require a specific check: metadata, execution targets, documented injection filenames/configs, or project font validation. Project membership, source extensions and executable bits do not select arbitrary files. Use -broad for broader non-dependency inspection"})
	}
	if s.SkipTempRoots {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: "temp", Detail: "Temp directories were not walked (-skip-tmproots): a payload unpacked into a subdirectory of one was not looked for. The documented staging filenames are still checked at the top of each temp directory, and a temp directory named with -root is still walked in full"})
		s.checkSkippedTempTops()
	}
	s.scanSharedDiscovery()
	if s.Deep {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: "dependencies", Detail: "Dependency checks select declared npm entrypoints, Python command modules/startup files, Composer autoload files, and known payload candidates. Unreferenced source, type exports, wildcard/subpath exports and transitive imports are not exhaustively read"})
	}

	// Phase 3: Find and scan Python site-packages directories. The phase still
	// runs under -only: a virtualenv inside a requested root is in scope, and
	// the fixed system paths are filtered out by the same scope rule.
	s.phase("Scanning Python site-packages")
	s.debug.stage("python")
	s.scanPythonPackages()

	// Phases 4 and 5: Check running command lines and network IOCs. Both
	// describe the machine, not a directory, so -only runs neither — and
	// therefore does not count or print them. The banner already says so.
	if !s.Only {
		s.phase("Scanning running processes")
		s.debug.stage("processes")
		s.checkProcesses()

		s.phase("Scanning active network connections")
		s.debug.stage("network")
		s.checkNetworkIOCs()
	}

	// A scan that spent its whole stall budget stops here rather than running
	// Git over the same unresponsive storage. Git bounds itself per repository,
	// but the report is already untrustworthy and the reader's next move is to
	// fix the machine and re-run, not to read a longer partial result.
	s.stats.GitSkipped = s.Git && s.stallBudgetSpent()
	if s.Git && !s.stats.GitSkipped {
		s.phase("Scanning locally available Git refs and history")
		s.debug.stage("git")
		s.scanGitRepositories()
	}

	s.finalizeStalls()

	s.stats.ContentBytesRead = s.contentIO.bytes.Load()
	// Count the named files rather than the reads, so the summary number is
	// exactly the list the saved report carries.
	s.stats.BinaryPrefixesSkipped = 0
	for _, f := range s.Findings {
		if f.Check == "scan-limited" && f.Detail == binaryExcludedDetail {
			s.stats.BinaryPrefixesSkipped++
		}
	}
	s.stats.Deep = s.Deep
	s.stats.Git = s.Git
	if !s.Only {
		s.stats.HomeRoot = s.HomeDir
	}
	s.stats.Duration = time.Since(start)
	s.stats.Debug = s.debug.snapshot()
	return s.Findings, s.stats
}

// checkArtifacts looks for known malicious files at fixed paths.
func (s *Scanner) checkArtifacts() {
	var checks []ArtifactCheck

	switch runtime.GOOS {
	case "darwin":
		checks = append(checks, ArtifactsDarwin...)
	case "windows":
		checks = append(checks, ArtifactsWindows()...)
	case "linux":
		checks = append(checks, ArtifactsLinux...)
	}
	checks = append(checks, ArtifactsCrossPlatform...)

	for _, c := range checks {
		path := c.Path
		if !c.Absolute {
			path = filepath.Join(s.HomeDir, c.Path)
		}
		if !s.pathInScope(path) {
			continue
		}

		s.log("checking artifact: %s", path)
		s.stats.FilesChecked++
		if _, err := os.Stat(path); err == nil {
			s.addFinding(Finding{
				Check:    "known-artifact",
				Severity: SevCritical,
				Path:     path,
				Detail:   fmt.Sprintf("%s (attack: %s)", c.Desc, c.Attack),
			})
		}
	}
}

// scanProjectDirs walks home and each additional scan root, looking for node_modules to inspect
// for compromised npm packages AND for project-local config directories (.claude, .vscode)
// that supply chain attacks are known to drop payload files into.
func (s *Scanner) scanProjectDirs() {
	s.walkScanRoots(s.visitProject)
}

func (s *Scanner) visitProject(path string, d os.DirEntry, err error) error {
	if err != nil {
		s.scanError(path, err)
		return nil
	}

	if !d.IsDir() {
		if s.routineContentFile(path, d.Name(), d) {
			s.checkSourceFile(path, d.Name())
		}
		return nil
	}

	if d.Name() == ".git" {
		return filepath.SkipDir
	}
	if d.Name() == "site-packages" {
		return s.persistenceOrDescend(path)
	}
	if d.Name() == "node_modules" {
		// Nested node_modules (node_modules inside node_modules) get no
		// second round of package-level checks, but in deep mode the walk
		// still descends so their file contents are read.
		if strings.Contains(filepath.Dir(path), "node_modules") {
			return s.persistenceOrDescend(path)
		}
		s.stats.NodeModulesFound++
		s.log("found node_modules: %s", path)
		s.checkNodeModulesDir(path)
		return s.persistenceOrDescend(path)
	}

	if files, ok := KnownProjectArtifacts[d.Name()]; ok {
		s.log("checking project config dir: %s", path)
		s.checkProjectArtifactDir(path, files)
		if s.Deep {
			// Descend instead, so nested files are read too.
			return nil
		}
		// The walk stops here, so inspect this directory's own files
		// before returning — `.vscode/tasks.json` is the PolinRider
		// loader and would otherwise never be read.
		s.scanDirFiles(path)
		return s.persistenceOrDescend(path)
	}

	// A composer vendor/ directory is identified by the presence of
	// vendor/composer/installed.json. We don't blindly SkipDir on every
	// "vendor" since that name is reused by Go modules and others — only
	// stop recursing when we've confirmed it's a Composer install.
	if d.Name() == "vendor" {
		installedJSON := filepath.Join(path, "composer", "installed.json")
		if _, err := os.Stat(installedJSON); err == nil {
			if strings.Contains(filepath.Dir(path), "vendor") {
				return s.persistenceOrDescend(path)
			}
			s.stats.ComposerVendorsFound++
			s.log("found composer vendor: %s", path)
			s.checkComposerVendor(path)
			return s.persistenceOrDescend(path)
		}
	}

	return nil
}

// descendOrSkip returns the walk verdict for a dependency directory whose
// package-level checks have just run: stop here normally, or keep walking in
// deep mode to discover nested metadata and known candidate names.
func (s *Scanner) descendOrSkip() error {
	if s.Deep {
		return nil
	}
	return filepath.SkipDir
}

// checkNpmPayloadFiles looks for known malicious filenames inside a single npm
// package directory in node_modules. Used to catch documented payload files
// (e.g. router_init.js dropped into @tanstack packages) independently of the
// package's declared version, so leftover artifacts after partial cleanup or
// version-string tampering are still detected.
func (s *Scanner) checkNpmPayloadFiles(pkgDir, pkgName string, files []ProjectArtifact) {
	for _, p := range files {
		path := filepath.Join(pkgDir, p.Filename)
		s.stats.FilesChecked++
		if _, err := os.Stat(path); err == nil {
			s.addFinding(Finding{
				Check:    "npm-payload-file",
				Severity: SevCritical,
				Path:     path,
				Detail:   fmt.Sprintf("%s contains %s (attack: %s)", pkgName, p.Desc, p.Attack),
			})
		}
	}
}

// checkProjectArtifactDir looks for known malicious filenames inside a project-local
// config directory (.claude, .vscode, etc.). Each match is a critical finding.
func (s *Scanner) checkProjectArtifactDir(dir string, files []ProjectArtifact) {
	for _, a := range files {
		path := filepath.Join(dir, a.Filename)
		s.stats.FilesChecked++
		if _, err := os.Stat(path); err == nil {
			s.addFinding(Finding{
				Check:    "project-artifact",
				Severity: SevCritical,
				Path:     path,
				Detail:   fmt.Sprintf("%s (attack: %s)", a.Desc, a.Attack),
			})
		}
	}
}

// checkNodeModulesDir runs all npm-related checks on a single node_modules directory.
func (s *Scanner) checkNodeModulesDir(nmDir string) {
	// Check 1: Phantom dependencies
	for _, pkg := range KnownPhantomPackages {
		pkgDir := filepath.Join(nmDir, pkg)
		if _, err := os.Stat(pkgDir); err == nil {
			s.addFinding(Finding{
				Check:    "phantom-dependency",
				Severity: SevCritical,
				Path:     pkgDir,
				Detail:   fmt.Sprintf("Known malicious phantom package '%s' found", pkg),
			})
		}
	}

	// Check 3: Lifecycle scripts + npm payload files for every package
	s.scanNodeModulesPackages(nmDir)
}

// scanNodeModulesPackages walks each package directory under nmDir and runs
// lifecycle-script and npm-payload-file checks. Scoped packages (@org/*) and
// unscoped packages are both supported; KnownNpmPayloadFiles keys may be a
// scope name (checked against every package under that scope) or an exact
// unscoped package name.
func (s *Scanner) scanNodeModulesPackages(nmDir string) {
	entries, err := s.readDir(nmDir)
	if err != nil {
		s.scanError(nmDir, err)
		return
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") || !s.packageDirectory(filepath.Join(nmDir, entry.Name()), entry) {
			continue
		}

		// Scoped packages (@org/pkg)
		if strings.HasPrefix(entry.Name(), "@") {
			scopeDir := filepath.Join(nmDir, entry.Name())
			scopedEntries, err := s.readDir(scopeDir)
			if err != nil {
				s.scanError(scopeDir, err)
				continue
			}
			payloadFiles := KnownNpmPayloadFiles[entry.Name()]
			for _, se := range scopedEntries {
				if !s.packageDirectory(filepath.Join(scopeDir, se.Name()), se) {
					continue
				}
				pkgDir := filepath.Join(scopeDir, se.Name())
				pkgName := entry.Name() + "/" + se.Name()
				s.checkPackage(pkgDir, pkgName)
				s.checkNpmPayloadFiles(pkgDir, pkgName, payloadFiles)
			}
			continue
		}

		// Unscoped packages: lifecycle-script checks, then any package-name
		// payload-file entries (e.g. keyv → setup.mjs / Math_Symbol.js).
		pkgDir := filepath.Join(nmDir, entry.Name())
		s.checkPackage(pkgDir, entry.Name())
		if payloadFiles := KnownNpmPayloadFiles[entry.Name()]; len(payloadFiles) > 0 {
			s.checkNpmPayloadFiles(pkgDir, entry.Name(), payloadFiles)
		}
	}
}

// Explicit package metadata checks follow package-directory symlinks, including
// pnpm layouts. This does not make the recursive content walker follow them.
func (s *Scanner) packageDirectory(path string, entry os.DirEntry) bool {
	if entry.IsDir() {
		return true
	}
	if entry.Type()&os.ModeSymlink == 0 {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		s.scanError(path, err)
		return false
	}
	return info.IsDir()
}

// packageJSON represents the relevant fields of a package.json.
type packageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
	Main    json.RawMessage   `json:"main"`
	Module  json.RawMessage   `json:"module"`
	Bin     json.RawMessage   `json:"bin"`
	Exports json.RawMessage   `json:"exports"`
}

// checkPackage examines a single package for red flags.
func (s *Scanner) checkPackage(pkgDir, pkgName string) {
	s.checkPackageManifest(pkgDir, pkgName, true)
}
func (s *Scanner) checkPackageManifest(pkgDir, pkgName string, optional bool) {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")
	if s.packageChecked == nil {
		s.packageChecked = make(map[string]bool)
	}
	if s.packageChecked[pkgJSONPath] {
		return
	}
	s.packageChecked[pkgJSONPath] = true

	if s.processFileMode(pkgJSONPath, ReadTimeout, func(local *Scanner, data []byte) {
		// package.json is also used by non-npm applications (e.g. OBS).
		// Recognize that shape before imposing npm's version schema.
		if nonNpmUpdateManifest(data) {
			local.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: pkgJSONPath, Detail: "Non-npm update manifest; npm package/version and lifecycle checks do not apply"})
			return
		}
		var pkg packageJSON
		if err := json.Unmarshal(data, &pkg); err != nil || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
			if err == nil {
				err = fmt.Errorf("expected an object")
			}
			local.scanError(pkgJSONPath, fmt.Errorf("invalid package manifest: %w", err))
			return
		}
		local.inspectGeneralContent(pkgJSONPath, data)
		for _, bad := range KnownBadNpmVersions[pkgName] {
			if pkg.Version == bad {
				local.addFinding(Finding{Check: "compromised-version", Severity: SevCritical, Path: pkgJSONPath, Detail: fmt.Sprintf("Known compromised version %s@%s", pkgName, pkg.Version)})
			}
		}
		local.inspectPackageScripts(pkgDir, pkgName, &pkg)
		if local.Deep {
			local.inspectPackageEntrypoints(pkgDir, &pkg)
		}
		if !hasIncomplete(local.Findings) {
			local.stats.PackagesScanned++
		}
	}, optional) != nil {
		s.stats.FilesChecked++
	}
}

func (s *Scanner) inspectPackageScripts(pkgDir, pkgName string, pkg *packageJSON) {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")

	// Check for suspicious lifecycle scripts. `prepare` is included because the
	// Mini Shai-Hulud TanStack sub-incident uses it (e.g.
	// "prepare": "bun run tanstack_runner.js && exit 1") — npm runs `prepare`
	// on local installs and on `npm pack`, so it's a viable malware vehicle.
	// Additional prepublish/pack hooks are selected according to npm lifecycle
	// semantics; their presence alone is not a finding.
	// https://docs.npmjs.com/cli/v11/using-npm/scripts/
	// https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json
	suspiciousHooks := []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}
	for _, hook := range suspiciousHooks {
		script, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		issues := analyzeScript(script)
		if standardYarnPreinstall(pkgName, pkg.Name, hook, script) {
			issues = nil
		}
		if len(issues) > 0 {
			s.addFinding(Finding{
				Check:    "suspicious-install-script",
				Severity: SevWarn,
				Path:     pkgJSONPath,
				Detail:   fmt.Sprintf("%s has suspicious %s script: %s (flags: %s)", pkgName, hook, truncate(script, 80), strings.Join(issues, ", ")),
			})
		}

		// If the script references a JS file, check it for obfuscation
		if jsFile := extractScriptTarget(script); jsFile != "" {
			s.checkScriptTarget(filepath.Join(pkgDir, jsFile), pkgName, hook)
		}
	}
}

// standardYarnPreinstall exempts only the official Yarn command from lifecycle
// string heuristics. The referenced JS file is still inspected for obfuscation.
// https://github.com/yarnpkg/yarn/blob/v1.22.22/scripts/update-dist-manifest.js
func standardYarnPreinstall(pkgName, manifestName, hook, script string) bool {
	return pkgName == "yarn" && manifestName == "yarn" && hook == "preinstall" &&
		script == ":; (node ./preinstall.js > /dev/null 2>&1 || true)"
}

// analyzeScript checks a lifecycle script string for red flags.
func analyzeScript(script string) []string {
	var flags []string
	lower := strings.ToLower(script)

	patterns := []struct {
		substr string
		flag   string
	}{
		{"curl ", "downloads-via-curl"},
		{"wget ", "downloads-via-wget"},
		{"powershell", "uses-powershell"},
		{"-executionpolicy bypass", "bypasses-execution-policy"},
		{"eval(", "uses-eval"},
		{"eval ", "uses-eval"},
		{"base64", "uses-base64"},
		{"\\x", "hex-encoded-strings"},
		{"nohup ", "background-process"},
		{"> /dev/null", "suppresses-output"},
		{"-windowstyle hidden", "hidden-window"},
		{".vbs", "uses-vbscript"},
		{"osascript", "uses-applescript"},
	}

	for _, p := range patterns {
		if strings.Contains(lower, p.substr) {
			flags = append(flags, p.flag)
		}
	}

	if matchesDecodeExecute([]byte(script)) {
		flags = append(flags, "decode-and-execute")
	}
	if downloadShell.MatchString(script) {
		flags = append(flags, "download-to-shell")
	}
	if victimAssignment.MatchString(script) && strings.Contains(script, " -e") {
		flags = append(flags, "inline-global-bootstrap")
	}
	if taskRunsAsset(vscodeTask{Command: json.RawMessage(strconv.Quote(script))}) {
		flags = append(flags, "interpreter-to-asset")
	}
	return flags
}

// extractScriptTarget pulls out a JS filename from a "node foo.js" style script,
// including a shell subshell wrapper such as Yarn's "(node ./preinstall.js …)".
func extractScriptTarget(script string) string {
	tokens := shellTokens.FindAllString(script, -1)
	for i, token := range tokens {
		if !nodeExecutable(token) || i+1 >= len(tokens) {
			continue
		}
		target := strings.Trim(tokens[i+1], `"'`)
		if strings.HasPrefix(target, "-") {
			continue
		}
		if isJSFamily(strings.ToLower(filepath.Ext(target))) {
			return target
		}
	}

	return ""
}

// checkFileObfuscation reads a JS file and checks for obfuscation patterns.
func (s *Scanner) checkScriptFile(path, pkgName string) { s.checkScriptTarget(path, pkgName, "") }

// A lifecycle script naming a file that is not on disk is an upstream packaging
// defect, not a failed read: build hooks are commonly stripped from published
// tarballs, and pruned installs drop install helpers. Saying so plainly beats
// reporting it as a path surplies could not inspect. It is informational, not
// a warning: the absence is normal and nearly always benign, and the reader has
// nothing to review beyond the packaging itself.
func (s *Scanner) checkScriptTarget(path, pkgName, hook string) {
	// The target is named by the manifest, relative to the package, so "../"
	// resolves outside it — and npm would run it there, which is why the
	// escape is inspected rather than ignored. Under -only that read and the
	// finding naming it would land outside the tree the user asked about,
	// which is the one thing -only promises not to do. Without -only this is
	// a no-op and the target is inspected wherever it points.
	if !s.pathInScope(path) {
		return
	}
	if hook != "" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			s.addFinding(Finding{Check: "missing-script-target", Severity: SevInfo, Path: path, rollup: fmt.Sprintf("%s (%s)", pkgName, hook), Detail: fmt.Sprintf("%s declares a %s script that runs this file, but no such file is installed; npm would execute anything later written to this path", pkgName, hook)})
			return
		}
	}
	if s.scriptChecked == nil {
		s.scriptChecked = make(map[string]bool)
	}
	if s.scriptChecked[path] {
		return
	}
	s.scriptChecked[path] = true
	if s.processFile(path, ReadTimeout, func(local *Scanner, data []byte) {
		local.inspectGeneralContent(path, data)
		if flags := obfuscationFlags(data); len(flags) > 0 {
			local.addFinding(Finding{Check: "obfuscated-install-script", Severity: SevWarn, Path: path, Detail: fmt.Sprintf("%s lifecycle target contains review patterns (flags: %s); these patterns alone do not establish compromise", pkgName, strings.Join(flags, ", "))})
		}
	}) != nil {
		s.stats.FilesChecked++
	}
}
func obfuscationFlags(data []byte) []string {
	content := string(data)
	var flags []string

	// High density of hex escapes
	if strings.Count(content, "\\x") > 20 {
		flags = append(flags, "heavy-hex-escapes")
	}

	// XOR operations in short file
	if len(data) < 10000 && strings.Count(content, "^") > 10 {
		flags = append(flags, "xor-operations")
	}

	// Multiple base64 decode calls
	b64Count := strings.Count(strings.ToLower(content), "base64") +
		strings.Count(content, "atob(") +
		strings.Count(content, "Buffer.from(")
	if b64Count > 3 {
		flags = append(flags, "heavy-base64-usage")
	}

	// eval or Function() constructor usage
	if strings.Contains(content, "eval(") || strings.Contains(content, "Function(") {
		flags = append(flags, "dynamic-code-execution")
	}

	// String concatenation building up module names (evasion technique)
	concatCount := strings.Count(content, "'+'") + strings.Count(content, `"+"`)
	if concatCount > 15 {
		flags = append(flags, "excessive-string-concat")
	}

	// fs.unlink(__filename) - self-deletion
	if strings.Contains(content, "unlink(__filename") || strings.Contains(content, "unlink(__dirname") {
		flags = append(flags, "self-deletion")
	}

	return flags
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Reuse the project walk for persistence discovery. Only pruned dependency or
// config trees need a separate names/entrypoints-only walk in default mode.
func (s *Scanner) persistenceOrDescend(path string) error {
	if s.Deep {
		return nil
	}
	s.walkPersistenceRoot(path)
	return filepath.SkipDir
}

func nonNpmUpdateManifest(data []byte) bool {
	var shape map[string]json.RawMessage
	return json.Unmarshal(data, &shape) == nil && shape["name"] == nil && shape["scripts"] == nil && shape["main"] == nil && shape["exports"] == nil && shape["url"] != nil && shape["files"] != nil
}
