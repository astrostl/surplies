package main

import (
	"encoding/json"
	"fmt"
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
	NodeModulesFound      int
	PackagesScanned       int
	SitePackagesFound     int
	PythonPackagesScanned int
	FilesChecked          int
	Duration              time.Duration
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

	// Phase 2: Find and scan node_modules directories
	fmt.Fprintf(os.Stderr, "[2/5] Scanning node_modules for compromised packages...\n")
	s.scanNodeModules()

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
	fmt.Fprintf(os.Stderr, "\nScan complete in %s\n", s.stats.Duration.Round(time.Millisecond))

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

// scanNodeModules walks the home directory looking for node_modules.
func (s *Scanner) scanNodeModules() {
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

		return nil
	})
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

	// Check 3: Scan all packages for suspicious postinstall scripts
	entries, err := os.ReadDir(nmDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		// Handle scoped packages (@org/pkg)
		if strings.HasPrefix(entry.Name(), "@") {
			scopeDir := filepath.Join(nmDir, entry.Name())
			scopedEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, se := range scopedEntries {
				if se.IsDir() {
					s.checkPackage(filepath.Join(scopeDir, se.Name()), entry.Name()+"/"+se.Name())
				}
			}
			continue
		}

		s.checkPackage(filepath.Join(nmDir, entry.Name()), entry.Name())
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

	// Check for suspicious lifecycle scripts
	suspiciousHooks := []string{"preinstall", "install", "postinstall"}
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

	// Check for version mismatch (self-healing artifact detection)
	if pkg.Version != "" && pkg.Name != "" {
		dirName := filepath.Base(pkgDir)
		// If this package reports as a different name than its directory, flag it
		baseName := pkg.Name
		if strings.Contains(baseName, "/") {
			parts := strings.SplitN(baseName, "/", 2)
			baseName = parts[1]
		}
		// Allow known aliasing patterns (e.g., strip-ansi-cjs -> strip-ansi)
		isAlias := strings.HasSuffix(dirName, "-cjs") && baseName == strings.TrimSuffix(dirName, "-cjs")
		if baseName != dirName && !isAlias {
			s.addFinding(Finding{
				Check:    "package-name-mismatch",
				Severity: SevWarn,
				Path:     pkgJSONPath,
				Detail:   fmt.Sprintf("Directory '%s' contains package named '%s' (possible artifact swap)", dirName, pkg.Name),
			})
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

// checkNetworkIOCs checks active network connections for known C2 indicators.
// Runs netstat twice in parallel: once with -n (numeric, for IP matching) and
// once without (with hostname resolution, for domain matching).
func (s *Scanner) checkNetworkIOCs() {
	var (
		outNumeric  []byte
		outResolved []byte
		wg          sync.WaitGroup
	)

	s.log("running netstat -n (IPs) and netstat (domains) in parallel")
	wg.Add(2)
	go func() {
		defer wg.Done()
		outNumeric, _ = exec.Command("netstat", "-n").Output()
	}()
	go func() {
		defer wg.Done()
		outResolved, _ = exec.Command("netstat").Output()
	}()
	wg.Wait()
	s.log("netstat complete: %d bytes numeric, %d bytes resolved", len(outNumeric), len(outResolved))

	seen := make(map[string]bool)
	checkContent := func(content string, iocs []string) {
		for _, ioc := range iocs {
			if !seen[ioc] && strings.Contains(content, ioc) {
				seen[ioc] = true
				s.addFinding(Finding{
					Check:    "network-ioc-active-connection",
					Severity: SevCritical,
					Path:     "netstat",
					Detail:   fmt.Sprintf("Active connection to known C2 indicator '%s'", ioc),
				})
			}
		}
	}

	checkContent(string(outNumeric), KnownC2IPs)
	checkContent(string(outResolved), KnownC2Domains)
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
