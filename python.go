package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// distInfoVersionRe matches the version portion of a .dist-info directory name.
// e.g., "litellm-1.82.7.dist-info" -> package "litellm", version "1.82.7"
var distInfoVersionRe = regexp.MustCompile(`^(.+)-(\d+\..+)\.dist-info$`)

// scanPythonPackages walks the home directory looking for site-packages directories
// and checks them for compromised packages and malicious .pth files.
func (s *Scanner) scanPythonPackages() {
	// Also check well-known system paths outside home dir for .pth files and bad versions.
	systemPaths := pythonSystemPaths()

	for _, sp := range systemPaths {
		entries, err := os.ReadDir(sp)
		if err != nil {
			continue
		}
		s.log("found site-packages: %s", sp)
		s.stats.SitePackagesFound++
		s.checkSitePackagesDir(sp, entries)
	}

	// Walk home dir for virtualenvs and ~/.local site-packages
	filepath.WalkDir(s.HomeDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == "site-packages" {
			s.stats.SitePackagesFound++
			s.log("found site-packages: %s", path)
			entries, err := os.ReadDir(path)
			if err != nil {
				return filepath.SkipDir
			}
			s.checkSitePackagesDir(path, entries)
			return filepath.SkipDir
		}
		return nil
	})
}

// checkSitePackagesDir runs all Python-related checks on a single site-packages directory.
func (s *Scanner) checkSitePackagesDir(spDir string, entries []os.DirEntry) {
	for _, entry := range entries {
		name := entry.Name()

		// Check for known malicious .pth files
		if strings.HasSuffix(name, ".pth") {
			s.checkPthFile(spDir, name)
			continue
		}

		// Check .dist-info directories for known bad versions
		if entry.IsDir() && strings.HasSuffix(name, ".dist-info") {
			s.checkDistInfo(spDir, name)
			continue
		}
	}
}

// checkPthFile checks a .pth file for known malicious filenames and suspicious content.
func (s *Scanner) checkPthFile(spDir, filename string) {
	path := filepath.Join(spDir, filename)
	s.stats.FilesChecked++

	// Check against known malicious .pth filenames
	for _, known := range KnownMaliciousPthFiles {
		if filename == known {
			s.addFinding(Finding{
				Check:    "malicious-pth-file",
				Severity: SevCritical,
				Path:     path,
				Detail:   fmt.Sprintf("Known malicious .pth file '%s' found", filename),
			})
			return
		}
	}

	// Heuristic: check .pth content for suspicious patterns.
	// Legitimate .pth files contain import paths (one per line) or "import" statements
	// for simple path setup. Malicious ones contain encoded payloads and shell commands.
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	issues := analyzePthContent(content)
	if len(issues) > 1 {
		s.addFinding(Finding{
			Check:    "suspicious-pth-file",
			Severity: SevWarn,
			Path:     path,
			Detail:   fmt.Sprintf("Suspicious .pth file content (flags: %s)", strings.Join(issues, ", ")),
		})
	}
}

// analyzePthContent checks .pth file content for red flags.
func analyzePthContent(content string) []string {
	var flags []string

	patterns := []struct {
		substr string
		flag   string
	}{
		{"subprocess", "uses-subprocess"},
		{"base64", "uses-base64"},
		{"exec(", "uses-exec"},
		{"eval(", "uses-eval"},
		{"compile(", "uses-compile"},
		{"os.system", "uses-os-system"},
		{"urllib", "uses-urllib"},
		{"requests", "uses-requests"},
		{"socket", "uses-socket"},
		{"\\x", "hex-encoded-strings"},
		{"/bin/sh", "shell-execution"},
		{"/bin/bash", "shell-execution"},
		{"powershell", "uses-powershell"},
	}

	lower := strings.ToLower(content)
	for _, p := range patterns {
		if strings.Contains(lower, p.substr) {
			flags = append(flags, p.flag)
		}
	}

	// Large .pth files are unusual — legitimate ones are typically a few lines
	if len(content) > 5000 {
		flags = append(flags, "unusually-large")
	}

	return flags
}

// checkDistInfo checks a .dist-info directory for known compromised versions.
func (s *Scanner) checkDistInfo(spDir, dirName string) {
	m := distInfoVersionRe.FindStringSubmatch(dirName)
	if m == nil {
		return
	}
	// Normalize package name: PyPI uses hyphens in dist-info but packages may use underscores
	pkgName := strings.ReplaceAll(strings.ToLower(m[1]), "_", "-")
	version := m[2]
	s.stats.PythonPackagesScanned++

	badVersions, ok := KnownBadPythonVersions[pkgName]
	if !ok {
		return
	}
	for _, bad := range badVersions {
		if version == bad {
			s.addFinding(Finding{
				Check:    "compromised-python-version",
				Severity: SevCritical,
				Path:     filepath.Join(spDir, dirName),
				Detail:   fmt.Sprintf("Known compromised version %s==%s", pkgName, version),
			})
		}
	}
}

// pythonSystemPaths returns well-known system Python site-packages paths to check.
func pythonSystemPaths() []string {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		winPrefixes := []string{
			`C:\Python3*`,
			`C:\Program Files\Python3*`,
		}
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			winPrefixes = append(winPrefixes, filepath.Join(localAppData, "Programs", "Python", "Python3*"))
		}
		for _, prefix := range winPrefixes {
			matches, _ := filepath.Glob(prefix)
			for _, m := range matches {
				paths = append(paths, filepath.Join(m, "Lib", "site-packages"))
			}
		}
	default:
		unixPrefixes := []string{
			"/usr/lib/python3.*",
			"/usr/local/lib/python3.*",
			"/opt/homebrew/lib/python3.*",
		}
		for _, prefix := range unixPrefixes {
			matches, _ := filepath.Glob(prefix)
			for _, m := range matches {
				paths = append(paths, filepath.Join(m, "site-packages"))
			}
		}
	}

	return paths
}
