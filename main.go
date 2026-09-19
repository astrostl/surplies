package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
)

var version = "dev"

func init() {
	if version != "dev" {
		return // ldflags already set it
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
}

func main() {
	var (
		jsonOutput bool
		quiet      bool
		showVer    bool
		extraRoots []string
	)

	flag.BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&quiet, "q", false, "suppress scan details")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.BoolVar(&showVer, "v", false, "") // undocumented -v/--v alias
	modes := registerScanModes(flag.CommandLine)
	flag.Func("root", "add/expand a directory to the full scan (repeatable)", func(path string) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("scan root must not be empty")
		}
		extraRoots = append(extraRoots, path)
		return nil
	})
	flag.Usage = printUsage
	flag.Parse()

	if showVer {
		fmt.Printf("surplies %s\n", version)
		os.Exit(0)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	s := New(homeDir, !quiet)
	s.Deep = modes.Deep
	s.Git = modes.Git
	s.NpmCache = modes.NpmCache
	s.Broad = modes.Broad
	s.BrowserCache = modes.BrowserCache
	var debugLog *os.File
	if modes.Debug {
		s.debug, debugLog, err = openDebugLog("", quiet, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create debug log: %v\n", err)
			os.Exit(1)
		}
	}
	s.ExtraRoots = extraRoots
	findings, stats := s.Run()
	if debugLog != nil {
		if err := debugLog.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Could not close debug log: %v\n", err)
		}
	}

	invocation := invocationLabel(version, os.Args[1:])
	printResults(findings, stats, jsonOutput, modes.Coverage, invocation)

	// Exit code reflects worst severity
	exitCode := 0
	for _, f := range findings {
		if f.Severity == SevCritical {
			exitCode = 2
			break
		}
		if f.Severity == SevWarn && exitCode < 1 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

type scanModes struct {
	Deep, Git, Coverage, NpmCache, Debug, Broad, BrowserCache bool
}

func registerScanModes(fs *flag.FlagSet) *scanModes {
	m := &scanModes{Deep: true, Git: true, Coverage: true}
	fs.BoolVar(&m.Broad, "broad", false, "include unrelated text/data (slow)")
	fs.BoolVar(&m.BrowserCache, "browser-cache", false, "include browser cache contents (slow)")
	fs.BoolVar(&m.Debug, "debug", false, "save detailed diagnostics to a log and report; -q suppresses terminal debug output")
	fs.BoolVar(&m.NpmCache, "npm-cache", false, "include raw npm cache contents (slow)")
	return m
}

func printResults(findings []Finding, stats ScanStats, jsonOutput, coverageDetails bool, invocation string) {
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
		if stats.Debug != nil && stats.Debug.DebugLog != "" {
			fmt.Fprintf(os.Stderr, "Debug log saved: %s\n", stats.Debug.DebugLog)
		}
		printReportSummary(os.Stderr, findings, stats, invocation)
	} else {
		if path, err := saveScanReport("", findings, stats, invocation); err == nil {
			fmt.Fprintf(os.Stdout, "\n-----------------------------------------------------------------------------\n\nFull report saved: %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "Could not save full report: %v\n", err)
			printDiagnosticGroups(os.Stdout, findings)
		}
		if stats.Debug != nil && stats.Debug.DebugLog != "" {
			fmt.Fprintf(os.Stdout, "Debug log saved: %s\n", stats.Debug.DebugLog)
		}
		printHumanReport(os.Stdout, findings, stats, coverageDetails, invocation)
	}
}

// Coverage limitations are diagnostics, not indicators of compromise. Keep
// scan-incomplete records in JSON and the nonzero exit status for automation.
func splitFindings(findings []Finding) (indicators, coverage []Finding) {
	for _, f := range findings {
		if f.Check == "scan-incomplete" {
			coverage = append(coverage, f)
		} else if f.Check != "scan-limited" {
			indicators = append(indicators, f)
		}
	}
	return
}

var coverageCategories = []string{"size limit exceeded", "permission denied", "timed out", "Git errors", "network collection", "other errors"}

func groupCoverage(coverage []Finding) map[string][]Finding {
	groups := make(map[string][]Finding)
	for _, f := range coverage {
		category := f.coverageCategory
		if category == "" {
			category = "other errors"
		}
		groups[category] = append(groups[category], f)
	}
	return groups
}

func coverageSummary(groups map[string][]Finding) string {
	var counts []string
	for _, category := range coverageCategories {
		if n := len(groups[category]); n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", n, category))
		}
	}
	return "Coverage incomplete: " + strings.Join(counts, ", ") + "."
}

func printCoverage(coverage []Finding, details bool) {
	if len(coverage) == 0 {
		return
	}
	groups := groupCoverage(coverage)
	fmt.Printf("\n%s These are not attack indicators.\n", coverageSummary(groups))
	if !details {
		fmt.Println("Use -json to inspect the affected paths.")
		return
	}
	for _, category := range coverageCategories {
		group := groups[category]
		if len(group) == 0 {
			continue
		}
		fmt.Printf("\n  %s — %d path(s):\n", category, len(group))
		printDiagnosticGroups(os.Stdout, group)
	}
	fmt.Println()
}

// Human diagnostics explain each shared cause once, then list its paths.
// Normalize only the affected path; preserve other evidence and original JSON.
func printDiagnosticGroups(out io.Writer, findings []Finding) {
	groups := make(map[string][]string)
	var reasons []string
	for _, f := range findings {
		reason := f.Detail
		if strings.ContainsAny(f.Path, `/\\`) {
			reason = strings.ReplaceAll(reason, f.Path, "<path>")
		}
		if _, exists := groups[reason]; !exists {
			reasons = append(reasons, reason)
		}
		groups[reason] = append(groups[reason], f.Path)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		if reason != "" {
			fmt.Fprintf(out, "    %s\n", reason)
		}
		paths := groups[reason]
		sort.Strings(paths)
		for _, path := range paths {
			fmt.Fprintf(out, "      %s\n", path)
		}
	}
}

func invocationLabel(buildVersion string, args []string) string {
	parts := []string{"surplies", strings.TrimPrefix(buildVersion, "v")}
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\r\n\"\\") || arg == "" {
			arg = strconv.Quote(arg)
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

func resultSummary(invocation string, findings []Finding) string {
	indicators, coverage := splitFindings(findings)
	suffix := ""
	if len(coverage) > 0 {
		suffix = " Coverage was incomplete."
	}
	if len(indicators) == 0 {
		if len(findings) > 0 {
			return invocation + " : No supply chain attack indicators found in scanned content." + suffix
		}
		return invocation + " : No supply chain attack indicators found."
	}
	critical, warn, info := 0, 0, 0
	for _, f := range indicators {
		switch f.Severity {
		case SevCritical:
			critical++
		case SevWarn:
			warn++
		case SevInfo:
			info++
		}
	}
	if suffix != "" {
		suffix = "." + suffix
	}
	return fmt.Sprintf("%s : Found %d indicator(s): %d critical, %d warning, %d info", invocation, len(indicators), critical, warn, info) + suffix
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "surplies %s\n\n", version)
	fmt.Fprintln(out, "Usage: surplies [flags]")
	fmt.Fprintln(out)
	flag.VisitAll(func(f *flag.Flag) {
		name := f.Name
		if name == "v" {
			return
		}
		if name == "root" {
			name += " value"
		}
		fmt.Fprintf(out, "  -%s\n        %s\n", name, f.Usage)
	})
	fmt.Fprintln(out)
	fmt.Fprintln(out, defaultScanHelp(runtime.GOOS, defaultPersistenceRoots()))
}

func defaultScanHelp(goos string, roots []string) string {
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

// Expected scope limits stay visible but are neither collection failures nor
// attack indicators. JSON retains these INFO records; they do not change exit status.
func printScopeNotices(findings []Finding, details bool) {
	var notices []Finding
	for _, f := range findings {
		if f.Check == "scan-limited" {
			notices = append(notices, f)
		}
	}
	if len(notices) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "Limited scan scope — %d path(s). These are scope limits, not scan errors.\n", len(notices))
	if !details {
		fmt.Fprintln(os.Stderr, "Some checks have explicit scope limits; see the notices for unavailable coverage.")
		fmt.Fprintln(os.Stderr, "Use -json to inspect these scope notices.")
		return
	}
	printDiagnosticGroups(os.Stderr, notices)
}
