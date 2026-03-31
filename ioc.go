package main

import (
	"os"
	"path/filepath"
)

// --- npm ---

// KnownPhantomPackages are npm packages that exist solely as malware carriers
// and have no legitimate use. Their presence in node_modules is always suspicious.
var KnownPhantomPackages = []string{
	"plain-crypto-js",
}

// KnownBadNpmVersions maps legitimate npm package names to known-compromised versions.
var KnownBadNpmVersions = map[string][]string{
	"axios": {"1.14.1", "0.30.4"},
}

// --- Python/PyPI ---

// KnownBadPythonVersions maps legitimate PyPI package names to known-compromised versions.
// Package names are normalized (lowercase, hyphens) to match dist-info directory conventions.
var KnownBadPythonVersions = map[string][]string{
	"litellm": {"1.82.7", "1.82.8"},
}

// KnownMaliciousPthFiles are .pth filenames that are known malware delivery mechanisms.
var KnownMaliciousPthFiles = []string{
	"litellm_init.pth",
}

// --- Network IOCs ---

// KnownC2Domains are command-and-control domains from documented supply chain attacks.
// Each entry is sourced from a specific incident writeup.
var KnownC2Domains = []string{
	"sfrclak.com",          // axios — primary C2 domain (port 8000)
	"models.litellm.cloud", // litellm — credential exfiltration endpoint
	"checkmarx.zone",       // litellm — C2 polling endpoint (/raw)
}

// KnownC2IPs are command-and-control IP addresses from documented supply chain attacks.
var KnownC2IPs = []string{
	"142.11.206.73", // axios
}

// --- Filesystem artifacts ---

// ArtifactsDarwin are known malicious file paths on macOS (relative to home or absolute).
var ArtifactsDarwin = []ArtifactCheck{
	{Path: "/Library/Caches/com.apple.act.mond", Absolute: true, Desc: "axios RAT payload (macOS)", Attack: "axios 1.14.1/0.30.4"},
	{Path: "/tmp/6202033", Absolute: true, Desc: "axios AppleScript dropper (macOS)", Attack: "axios 1.14.1/0.30.4"},
}

// ArtifactsWindows returns known malicious file paths on Windows.
// Computed at runtime because ProgramData requires resolving %SystemDrive%.
func ArtifactsWindows() []ArtifactCheck {
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		programData = filepath.Join(drive, "ProgramData")
	}
	return []ArtifactCheck{
		{Path: filepath.Join(programData, `wt.exe`), Absolute: true, Desc: "PowerShell masquerading as Windows Terminal", Attack: "axios 1.14.1/0.30.4"},
	}
}

// ArtifactsLinux are known malicious file paths on Linux.
var ArtifactsLinux = []ArtifactCheck{
	{Path: "/tmp/ld.py", Absolute: true, Desc: "axios Python RAT payload (Linux)", Attack: "axios 1.14.1/0.30.4"},
}

// ArtifactsCrossPlatform are checked on all platforms (paths relative to home dir).
var ArtifactsCrossPlatform = []ArtifactCheck{
	// litellm C2 backdoor and persistence
	{Path: ".config/sysmon/sysmon.py", Absolute: false, Desc: "litellm C2 backdoor script", Attack: "litellm 1.82.7/1.82.8"},
	{Path: ".config/systemd/user/sysmon.service", Absolute: false, Desc: "litellm systemd persistence unit", Attack: "litellm 1.82.7/1.82.8"},
}

// ArtifactsTmp are checked in temp directories on all platforms.
var ArtifactsTmp = []struct {
	Glob string
	Desc string
}{
	// axios
	{"*.vbs", "axios VBScript dropper (Windows, %TEMP%\\{campaignID}.vbs)"},
	{"*.ps1", "axios PowerShell payload (Windows, %TEMP%\\{campaignID}.ps1)"},
	// litellm
	{".pg_state", "litellm C2 state tracking file"},
	{"pglog", "litellm downloaded payload staging"},
	{"tpcp.tar.gz", "litellm credential exfiltration archive"},
}
