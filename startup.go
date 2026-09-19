package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// These are defensive content hunts implemented by the community IR kit,
// not claims that DUNE used these persistence mechanisms.
// https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_macos.sh
// https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_linux.sh
var xmlComments = regexp.MustCompile(`(?s)<!--.*?-->`)

func startupPaths(home, goos string) (files, dirs []string) {
	if goos == "windows" {
		return []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")}, nil
	}
	for _, name := range []string{".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"} {
		files = append(files, filepath.Join(home, name))
	}
	files = append(files, "/etc/hosts", "/etc/profile", "/etc/bashrc", "/etc/zshrc", "/etc/crontab")
	if goos == "darwin" {
		dirs = []string{filepath.Join(home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"}
	}
	if goos == "linux" {
		dirs = []string{filepath.Join(home, ".config", "systemd", "user"), "/etc/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"}
	}
	return
}
func (s *Scanner) checkStartupFiles() {
	files, dirs := startupPaths(s.HomeDir, runtime.GOOS)
	s.inspectStartupPaths(files, dirs)
}
func (s *Scanner) inspectStartupPaths(files, dirs []string) {
	for _, path := range files {
		s.checkStartupFile(path, true)
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				s.scanError(path, err)
				return nil
			}
			if !d.IsDir() && d.Type()&os.ModeSymlink == 0 {
				s.checkStartupFile(path, false)
			}
			return nil
		})
	}
}
func startupPath(path string) bool {
	normalized := filepath.ToSlash(path)
	switch filepath.Base(path) {
	case ".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile":
		return true
	}
	for _, part := range []string{"/LaunchAgents/", "/LaunchDaemons/", "/systemd/", "/cron.d/", "/cron.daily/", "/cron.hourly/", "/cron.weekly/", "/cron.monthly/"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}
func (s *Scanner) checkStartupFile(path string, optional bool) {
	if s.persistenceChecked[path] {
		return
	}
	if optional {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
	}
	s.markPersistenceChecked(path)
	if s.processFile(path, ReadTimeout, func(local *Scanner, data []byte) {
		local.inspectStartupContent(path, data)
	}) != nil {
		s.stats.FilesChecked++
	}
}
func (s *Scanner) inspectHosts(path string, data []byte) {
	for line := range strings.Lines(string(data)) {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, ip := range KnownC2IPs {
			if canonicalIP(fields[0]) == canonicalIP(ip) {
				s.addFinding(Finding{Check: "hosts-c2-entry", Severity: SevWarn, Path: path, Detail: "Hosts file maps a name to a known C2 IP; this is configuration evidence, not an active connection"})
				return
			}
		}
	}
}

func containsIP(text, ip string) bool {
	for _, token := range strings.FieldsFunc(text, func(r rune) bool { return !(r >= '0' && r <= '9' || r == '.' || r == ':') }) {
		if canonicalIP(token) == canonicalIP(ip) {
			return true
		}
	}
	return false
}

func (s *Scanner) inspectStartupContent(path string, data []byte) {
	if bytes.HasPrefix(data, []byte("bplist00")) {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: path, Detail: "Binary plist startup content is not decoded; inspect it with separate plist tooling"})
		return
	}
	if filepath.Base(path) == "hosts" {
		s.inspectHosts(path, data)
		return
	}
	// Ignore ordinary shell/config comments. XML comments are removed separately.
	data = xmlComments.ReplaceAll(data, nil)
	var lines []string
	for line := range strings.Lines(string(data)) {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines = append(lines, line)
		}
	}
	clean := []byte(strings.Join(lines, ""))
	s.inspectGeneralContent(path, clean)
	text := string(clean)
	suspicious := strings.Contains(text, "/tmp/get-pip") || strings.Contains(text, "/tmp/.pip") || strings.Contains(text, "verify-human")
	if strings.Contains(text, ".node_modules") && (strings.Contains(text, "node ") || strings.Contains(text, "<string>node</string>") || strings.Contains(text, "ExecStart=")) {
		suspicious = true
	}
	for _, ip := range KnownC2IPs {
		if containsIP(text, ip) {
			suspicious = true
		}
	}
	if suspicious {
		s.addFinding(Finding{Check: "startup-content", Severity: SevWarn, Path: path, Detail: "Startup content references community-documented staging or C2 indicators; correlate with payload evidence"})
	}
}
