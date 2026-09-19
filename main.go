package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
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
	if len(os.Args) > 1 && os.Args[1] == "schedule" {
		if err := scheduleCommand(os.Args[2:], os.Stdout); err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var (
		jsonOutput      bool
		quiet           bool
		showVer         bool
		deep            bool
		extraRoots      []string
		coverageDetails bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&quiet, "q", false, "suppress scan details")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.BoolVar(&deep, "deep", false, "read file contents inside node_modules, vendor, and site-packages (slower)")
	flag.Func("root", "add/expand a directory to the normal scan (repeatable)", func(path string) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("scan root must not be empty")
		}
		extraRoots = append(extraRoots, path)
		return nil
	})
	flag.BoolVar(&coverageDetails, "cov", false, "show coverage failures grouped by cause")
	flag.Usage = printUsage
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument: %s\n", flag.Arg(0))
		os.Exit(1)
	}

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
	s.Deep = deep
	s.ExtraRoots = extraRoots
	findings, stats := s.Run()

	invocation := invocationLabel(version, os.Args[1:])
	printResults(findings, stats, jsonOutput, coverageDetails, invocation)

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

func printResults(findings []Finding, stats ScanStats, jsonOutput, coverageDetails bool, invocation string) {
	if jsonOutput {
		indicators, coverage := splitFindings(findings)
		if len(coverage) > 0 {
			fmt.Fprintln(os.Stderr, coverageSummary(groupCoverage(coverage))+" See scan-incomplete JSON records.")
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
		printScanSummary(stats)
		fmt.Fprintln(os.Stderr, resultSummary(invocation, indicators))
	} else {
		printFindings(findings, coverageDetails)
		printScanSummary(stats)
		indicators, _ := splitFindings(findings)
		fmt.Println(resultSummary(invocation, indicators))
	}

}

func printScanSummary(stats ScanStats) {

	// Surfaced rather than swallowed: a scan that walked past a synced folder
	// without reading any of it must not be mistaken for a scan that read it
	// and found nothing.
	if !stats.Deep {
		fmt.Fprintln(os.Stderr,
			"Note: dependency contents were not broadly scanned; only package checks and targeted application/npm persistence checks ran inside them. Re-run with -deep for dependency content scanning.")
	}

	if stats.FilesUnreadable > 0 {
		fmt.Fprintf(os.Stderr,
			"Note: %d file(s) could not be fully processed; see scan-incomplete findings for size limits, errors, or timeouts.\n",
			stats.FilesUnreadable)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Scan complete in %s\n", stats.Duration.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "Stats: %d node_modules (%d pkgs), %d site-packages (%d pkgs), %d composer vendors (%d pkgs), %d files checked\n",
		stats.NodeModulesFound, stats.PackagesScanned,
		stats.SitePackagesFound, stats.PythonPackagesScanned,
		stats.ComposerVendorsFound, stats.ComposerPackagesScanned,
		stats.FilesChecked)

	fmt.Fprintln(os.Stderr)
}

func printFindings(findings []Finding, coverageDetails bool) {
	indicators, coverage := splitFindings(findings)
	findings = indicators
	defer printCoverage(coverage, coverageDetails)
	if len(findings) == 0 {
		pkgs := make(map[string]bool)
		for pkg := range KnownBadNpmVersions {
			pkgs[pkg] = true
		}
		for pkg := range KnownBadPythonVersions {
			pkgs[pkg] = true
		}
		for pkg := range KnownBadComposerVersions {
			pkgs[pkg] = true
		}
		names := make([]string, 0, len(pkgs))
		for pkg := range pkgs {
			names = append(names, pkg)
		}
		sort.Strings(names)
		fmt.Printf("Checked for: %s.\n\n", strings.Join(names, ", "))
		fmt.Println()
		return
	}

	fmt.Fprintln(os.Stderr)

	for _, f := range findings {
		marker := " "
		switch f.Severity {
		case SevCritical:
			marker = "!"
		case SevWarn:
			marker = "?"
		}
		fmt.Printf("[%s] %s\n    %s\n    %s\n\n", marker, f.Check, f.Path, f.Detail)
	}
}

// Coverage limitations are diagnostics, not indicators of compromise. Keep
// scan-incomplete records in JSON and the nonzero exit status for automation.
func splitFindings(findings []Finding) (indicators, coverage []Finding) {
	for _, f := range findings {
		if f.Check == "scan-incomplete" {
			coverage = append(coverage, f)
		} else {
			indicators = append(indicators, f)
		}
	}
	return
}

var coverageCategories = []string{"size limit exceeded", "permission denied", "timed out", "other errors"}

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
		fmt.Println("Use -cov or -json to inspect the affected paths.")
		return
	}
	for _, category := range coverageCategories {
		group := groups[category]
		if len(group) == 0 {
			continue
		}
		fmt.Printf("\n  %s — %d path(s):\n", category, len(group))
		sort.Slice(group, func(i, j int) bool { return group[i].Path < group[j].Path })
		for _, f := range group {
			fmt.Printf("    %s\n", f.Path)
			if category == "other errors" {
				fmt.Printf("      %s\n", f.Detail)
			}
		}
	}
	fmt.Println()
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

func resultSummary(invocation string, indicators []Finding) string {
	if len(indicators) == 0 {
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
	return fmt.Sprintf("%s : Found %d indicator(s): %d critical, %d warning, %d info", invocation, len(indicators), critical, warn, info)
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "Usage: surplies [flags]\n       surplies schedule [-time HH:MM]\n       surplies schedule disable|remove\n\nSchedule daily scans with desktop notifications (default: 09:00 local time).")
	fmt.Fprintln(out)
	flag.VisitAll(func(f *flag.Flag) {
		name := f.Name
		if name == "root" {
			name += " value"
		}
		fmt.Fprintf(out, "  -%s\n        %s\n", name, f.Usage)
	})
	fmt.Fprintln(out)
	fmt.Fprintln(out, defaultScanHelp(runtime.GOOS, defaultPersistenceRoots()))
}

func defaultScanHelp(goos string, roots []string) string {
	home, example := "~", "/opt"
	if goos == "darwin" {
		example = "/Applications"
	}
	if goos == "windows" {
		home = "%USERPROFILE%"
		example = `"%ProgramFiles%"`
		if len(roots) > 0 {
			example = `"` + roots[0] + `"`
		}
	}
	system := strings.Join(roots, ", ")
	if system == "" {
		system = "none configured"
	}
	return fmt.Sprintf("Default normal scan: %s\nDefault persistence-only scans: %s\n\nNormal scans use supported file types and known checks, not every file.\n\nExample: surplies -root %s -deep", home, system, example)
}
