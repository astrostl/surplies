package scan

// Scan mode flags and the default-scope help text. These describe what the
// scanner does, not how the CLI is spelled, so they live with the scanner and
// its tests rather than in the command.

import (
	"flag"
	"fmt"
	"strings"
)

type ScanModes struct {
	Deep, Git, Coverage, NpmCache, Debug, Broad, BrowserCache, Resolve bool
	// SkipTempRoots drops the temp directories from the walk. The staging
	// names are still checked at the top of each one, so this narrows
	// traversal rather than putting temp directories out of scope entirely.
	SkipTempRoots bool
}

func RegisterScanModes(fs *flag.FlagSet) *ScanModes {
	m := &ScanModes{Deep: true, Git: true, Coverage: true}
	fs.BoolVar(&m.Broad, "broad", false, "include unrelated text/data (slow)")
	fs.BoolVar(&m.BrowserCache, "browser-cache", false, "include browser cache contents (slow)")
	fs.BoolVar(&m.Debug, "debug", false, "save detailed diagnostics to a log and report")
	fs.BoolVar(&m.NpmCache, "npm-cache", false, "include raw npm cache contents (slow)")
	fs.BoolVar(&m.Resolve, "resolve", false, "resolve and scan for known C2 domains (queries attacker-controlled nameservers)")
	fs.BoolVar(&m.SkipTempRoots, "skip-tmproots", false, "do not walk all temp directories (documented staging names are still checked)")
	return m
}

func DefaultScanHelp(goos string, roots []string) string {
	// The example must name somewhere that is NOT already a default root.
	// Suggesting one that is (e.g. /Applications on macOS) reads as advice to
	// add coverage that is already present, and for an app bundle the full
	// scan adds nothing anyway: *.app is a dependency directory, so routine
	// content reads stay suppressed there with or without -root.
	home, example, tempExample := homeLabel(goos), "/srv", "/tmp"
	if goos == "darwin" {
		example = "/Users/Shared"
	}
	if goos == "windows" {
		tempExample = `"%TEMP%"`
		example = `"%ProgramData%"`
	}
	system := strings.Join(roots, ", ")
	if system == "" {
		system = "none configured"
	}
	return fmt.Sprintf("Default full scan: %s\nDefault persistence-only scans: %s\n\nFull scans select manifests, execution targets, and documented injection candidates.\nContent: below 100 MB, five-second read/inspection deadline. Recognized assets get header checks.\nInternal directory symlinks are not followed, and archives are not unpacked.\n\nExample: surplies -root %s -root %s\n         surplies -root %s -only", home, system, example, tempExample, example)
}

// How the default root is spelled for the reader's shell. Help text and the
// zero-repository hint must name the same place.
func homeLabel(goos string) string {
	if goos == "windows" {
		return "%USERPROFILE%"
	}
	return "~"
}
