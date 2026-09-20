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
	Deep, Git, Coverage, NpmCache, Debug, Broad, BrowserCache bool
}

func RegisterScanModes(fs *flag.FlagSet) *ScanModes {
	m := &ScanModes{Deep: true, Git: true, Coverage: true}
	fs.BoolVar(&m.Broad, "broad", false, "include unrelated text/data (slow)")
	fs.BoolVar(&m.BrowserCache, "browser-cache", false, "include browser cache contents (slow)")
	fs.BoolVar(&m.Debug, "debug", false, "save detailed diagnostics to a log and report; -q suppresses terminal debug output")
	fs.BoolVar(&m.NpmCache, "npm-cache", false, "include raw npm cache contents (slow)")
	return m
}

func DefaultScanHelp(goos string, roots []string) string {
	// The example must name somewhere that is NOT already a default root.
	// Suggesting one that is (e.g. /Applications on macOS) reads as advice to
	// add coverage that is already present, and for an app bundle the full
	// scan adds nothing anyway: *.app is a dependency directory, so routine
	// content reads stay suppressed there with or without -root.
	home, example, tempExample := "~", "/srv", "/tmp"
	if goos == "darwin" {
		example = "/Users/Shared"
	}
	if goos == "windows" {
		home = "%USERPROFILE%"
		tempExample = `"%TEMP%"`
		example = `"%ProgramData%"`
	}
	system := strings.Join(roots, ", ")
	if system == "" {
		system = "none configured"
	}
	return fmt.Sprintf("Default full scan: %s\nDefault persistence-only scans: %s\n\nFull scans select manifests, execution targets, and documented injection candidates.\nContent: below 100 MB, five-second read/inspection deadline; recognized assets get header checks.\nInternal directory symlinks are not followed; archives are not unpacked.\n\nExample: surplies -root %s -root %s", home, system, example, tempExample)
}
