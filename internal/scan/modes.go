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
	home, example, tempExample := "~", "/opt", "/tmp"
	if goos == "darwin" {
		example = "/Applications"
	}
	if goos == "windows" {
		home = "%USERPROFILE%"
		tempExample = `"%TEMP%"`
		example = `"%ProgramFiles%"`
		if len(roots) > 0 {
			example = `"` + roots[0] + `"`
		}
	}
	system := strings.Join(roots, ", ")
	if system == "" {
		system = "none configured"
	}
	return fmt.Sprintf("Default full scan: %s\nDefault persistence-only scans: %s\n\nFull scans select manifests, execution targets, and documented injection candidates.\nContent: below 100 MB, five-second read/inspection deadline; recognized assets get header checks.\nInternal directory symlinks are not followed; archives are not unpacked.\n\nExample: surplies -root %s -root %s", home, system, example, tempExample)
}
