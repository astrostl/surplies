package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	stats    ScanStats
}

// ScanStats tracks scan progress.
type ScanStats struct {
	NodeModulesFound        int
	PackagesScanned         int
	SitePackagesFound       int
	PythonPackagesScanned   int
	ComposerVendorsFound    int
	ComposerPackagesScanned int
	FilesChecked            int
	Duration                time.Duration
}

// New creates a scanner targeting the given home directory.
func New(homeDir string, verbose bool) *Scanner {
	return &Scanner{
		HomeDir: homeDir,
		Verbose: verbose,
	}
}

func (s *Scanner) addFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Findings = append(s.Findings, f)
}

func (s *Scanner) log(format string, args ...any) {
	if s.Verbose {
		fmt.Fprintf(os.Stderr, "  [scan] "+format+"\n", args...)
	}
}

// Run executes all checks and returns findings.
func (s *Scanner) Run() ([]Finding, ScanStats) {
	start := time.Now()

	fmt.Fprintf(os.Stderr, "Scanning home directory: %s\n", s.HomeDir)
	fmt.Fprintf(os.Stderr, "Platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	// Phase 1: Check known malicious artifacts (fast, fixed paths)
	fmt.Fprintf(os.Stderr, "[1/5] Checking known malicious artifacts...\n")
	s.checkArtifacts()

	// Phase 2: Walk home for node_modules and project-local payload artifacts
	fmt.Fprintf(os.Stderr, "[2/5] Scanning project directories (node_modules, vendor, .claude, .vscode)...\n")
	s.scanProjectDirs()

	// Phase 3: Find and scan Python site-packages directories
	fmt.Fprintf(os.Stderr, "[3/5] Scanning Python site-packages for compromised packages...\n")
	s.scanPythonPackages()

	// Phase 4: Check for network IOCs in shell history/config
	fmt.Fprintf(os.Stderr, "[4/5] Checking active connections for network IOCs...\n")
	s.checkNetworkIOCs()

	// Phase 5: Check tmp directories for suspicious payload remnants
	fmt.Fprintf(os.Stderr, "[5/5] Checking temp directories for payload remnants...\n")
	s.checkTempArtifacts()

	s.stats.Duration = time.Since(start)
	fmt.Fprintln(os.Stderr)

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

// scanProjectDirs walks the home directory once, looking for node_modules to inspect
// for compromised npm packages AND for project-local config directories (.claude, .vscode)
// that supply chain attacks are known to drop payload files into.
func (s *Scanner) scanProjectDirs() {
	filepath.WalkDir(s.HomeDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible dirs
		}

		if !d.IsDir() {
			return nil
		}

		if d.Name() == "node_modules" {
			// Skip nested node_modules (node_modules inside node_modules)
			parent := filepath.Dir(path)
			if strings.Contains(parent, "node_modules") {
				return filepath.SkipDir
			}
			s.stats.NodeModulesFound++
			s.log("found node_modules: %s", path)
			s.checkNodeModulesDir(path)
			return filepath.SkipDir
		}

		if files, ok := KnownProjectArtifacts[d.Name()]; ok {
			s.log("checking project config dir: %s", path)
			s.checkProjectArtifactDir(path, files)
			return filepath.SkipDir
		}

		// A composer vendor/ directory is identified by the presence of
		// vendor/composer/installed.json. We don't blindly SkipDir on every
		// "vendor" since that name is reused by Go modules and others — only
		// stop recursing when we've confirmed it's a Composer install.
		if d.Name() == "vendor" {
			installedJSON := filepath.Join(path, "composer", "installed.json")
			if _, err := os.Stat(installedJSON); err == nil {
				parent := filepath.Dir(path)
				if strings.Contains(parent, "vendor") {
					return filepath.SkipDir
				}
				s.stats.ComposerVendorsFound++
				s.log("found composer vendor: %s", path)
				s.checkComposerVendor(path)
				return filepath.SkipDir
			}
		}

		return nil
	})
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

	// Check 2: Known bad versions
	for pkg, badVersions := range KnownBadNpmVersions {
		pkgJSON := filepath.Join(nmDir, pkg, "package.json")
		version := readPackageVersion(pkgJSON)
		if version == "" {
			continue
		}
		for _, bad := range badVersions {
			if version == bad {
				s.addFinding(Finding{
					Check:    "compromised-version",
					Severity: SevCritical,
					Path:     pkgJSON,
					Detail:   fmt.Sprintf("Known compromised version %s@%s", pkg, version),
				})
			}
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
	entries, err := os.ReadDir(nmDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		// Scoped packages (@org/pkg)
		if strings.HasPrefix(entry.Name(), "@") {
			scopeDir := filepath.Join(nmDir, entry.Name())
			scopedEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			payloadFiles := KnownNpmPayloadFiles[entry.Name()]
			for _, se := range scopedEntries {
				if !se.IsDir() {
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

// packageJSON represents the relevant fields of a package.json.
type packageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

func readPackageJSON(path string) *packageJSON {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	return &pkg
}

func readPackageVersion(path string) string {
	pkg := readPackageJSON(path)
	if pkg == nil {
		return ""
	}
	return pkg.Version
}

// checkPackage examines a single package for red flags.
func (s *Scanner) checkPackage(pkgDir, pkgName string) {
	pkgJSONPath := filepath.Join(pkgDir, "package.json")
	pkg := readPackageJSON(pkgJSONPath)
	if pkg == nil {
		return
	}
	s.stats.PackagesScanned++

	// Check for suspicious lifecycle scripts. `prepare` is included because the
	// Mini Shai-Hulud TanStack sub-incident uses it (e.g.
	// "prepare": "bun run tanstack_runner.js && exit 1") — npm runs `prepare`
	// on local installs and on `npm pack`, so it's a viable malware vehicle.
	suspiciousHooks := []string{"preinstall", "install", "postinstall", "prepare"}
	for _, hook := range suspiciousHooks {
		script, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		issues := analyzeScript(script)
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
			jsPath := filepath.Join(pkgDir, jsFile)
			if findings := checkFileObfuscation(jsPath); len(findings) > 0 {
				s.addFinding(Finding{
					Check:    "obfuscated-install-script",
					Severity: SevCritical,
					Path:     jsPath,
					Detail:   fmt.Sprintf("%s install script appears obfuscated (flags: %s)", pkgName, strings.Join(findings, ", ")),
				})
			}
		}
	}
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

	return flags
}

// extractScriptTarget pulls out a JS filename from a "node foo.js" style script.
func extractScriptTarget(script string) string {
	parts := strings.Fields(script)
	for i, p := range parts {
		if p == "node" && i+1 < len(parts) {
			target := parts[i+1]
			if strings.HasSuffix(target, ".js") {
				return target
			}
		}
	}
	return ""
}

// checkFileObfuscation reads a JS file and checks for obfuscation patterns.
func checkFileObfuscation(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
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

// resolveRoutableIPs resolves domain via the default resolver and returns only
// routable addresses. Unspecified (::, 0.0.0.0) and loopback results are
// dropped: sinkholed or blocked domains can resolve to ::, and substring-
// matching that against netstat output hits every IPv6 listener line.
func resolveRoutableIPs(ctx context.Context, domain string) []string {
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil
	}
	routable := ips[:0]
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsUnspecified() || parsed.IsLoopback() {
			continue
		}
		routable = append(routable, ip)
	}
	return routable
}

// checkNetworkIOCs checks active network connections for known C2 indicators.
// Runs netstat -n (no reverse DNS) and resolves known C2 domains to IPs in
// parallel, then matches resolved IPs against the netstat output. Forward DNS
// on the small known-bad list finishes in well under a second, vs. reverse DNS
// on every active connection which can take minutes on a busy machine.
func (s *Scanner) checkNetworkIOCs() {
	var (
		netstatOut []byte
		resolved   = make(map[string][]string)
		resolvedMu sync.Mutex
		wg         sync.WaitGroup
	)

	s.log("running netstat -n and resolving %d C2 domains in parallel", len(KnownC2Domains))

	wg.Go(func() {
		netstatOut, _ = exec.Command("netstat", "-n").Output()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, d := range KnownC2Domains {
		domain := d
		wg.Go(func() {
			routable := resolveRoutableIPs(ctx, domain)
			if len(routable) == 0 {
				return
			}
			resolvedMu.Lock()
			resolved[domain] = routable
			resolvedMu.Unlock()
		})
	}
	wg.Wait()

	totalIPs := 0
	for _, ips := range resolved {
		totalIPs += len(ips)
	}
	s.log("netstat complete: %d bytes; resolved %d/%d C2 domains to %d IPs", len(netstatOut), len(resolved), len(KnownC2Domains), totalIPs)

	content := string(netstatOut)
	seen := make(map[string]bool)

	for _, ip := range KnownC2IPs {
		if !seen[ip] && strings.Contains(content, ip) {
			seen[ip] = true
			s.addFinding(Finding{
				Check:    "network-ioc-active-connection",
				Severity: SevCritical,
				Path:     "netstat",
				Detail:   fmt.Sprintf("Active connection to known C2 indicator '%s'", ip),
			})
		}
	}

	for domain, ips := range resolved {
		if seen[domain] {
			continue
		}
		for _, ip := range ips {
			if strings.Contains(content, ip) {
				seen[domain] = true
				s.addFinding(Finding{
					Check:    "network-ioc-active-connection",
					Severity: SevCritical,
					Path:     "netstat",
					Detail:   fmt.Sprintf("Active connection to known C2 indicator '%s' (resolved to %s)", domain, ip),
				})
				break
			}
		}
	}
}

// checkTempArtifacts looks for suspicious files in temp directories.
func (s *Scanner) checkTempArtifacts() {
	tmpDirs := []string{os.TempDir()}

	if runtime.GOOS != "windows" {
		tmpDirs = append(tmpDirs, "/tmp", "/var/tmp")
	}

	seen := make(map[string]bool)
	for _, dir := range tmpDirs {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		s.log("checking temp dir: %s", dir)

		for _, sp := range ArtifactsTmp {
			matches, err := filepath.Glob(filepath.Join(dir, sp.Glob))
			if err != nil {
				continue
			}
			for _, m := range matches {
				s.stats.FilesChecked++
				s.addFinding(Finding{
					Check:    "suspicious-temp-file",
					Severity: SevWarn,
					Path:     m,
					Detail:   sp.Desc,
				})
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
