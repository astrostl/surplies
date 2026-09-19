package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	var (
		jsonOutput       bool
		quiet            bool
		showVer          bool
		deep             bool
		persistenceRoots []string
		coverageDetails  bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&quiet, "q", false, "quiet mode (suppress verbose scan details)")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.BoolVar(&deep, "deep", false, "read file contents inside node_modules, vendor/, and site-packages (slower, finds compromised dependencies that have no known advisory)")
	flag.Func("persistence-root", "additional directory to search recursively for documented persistence (repeatable)", func(path string) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("persistence root must not be empty")
		}
		persistenceRoots = append(persistenceRoots, path)
		return nil
	})
	flag.BoolVar(&coverageDetails, "coverage-details", false, "list individual paths with incomplete scan coverage")
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
	s.Deep = deep
	s.PersistenceRoots = persistenceRoots
	findings, stats := s.Run()

	invocation := invocationLabel(version, os.Args[1:])
	if jsonOutput {
		indicators, coverage := splitFindings(findings)
		fmt.Fprintln(os.Stderr, resultSummary(invocation, indicators))
		if len(coverage) > 0 {
			fmt.Fprintf(os.Stderr, "Coverage incomplete: %d path(s); see scan-incomplete JSON records.\n", len(coverage))
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		printFindings(findings, stats, coverageDetails, invocation)
	}

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

func printScanSummary(stats ScanStats) {
	fmt.Fprintf(os.Stderr, "Scan complete in %s\n", stats.Duration.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "Stats: %d node_modules (%d pkgs), %d site-packages (%d pkgs), %d composer vendors (%d pkgs), %d files checked\n",
		stats.NodeModulesFound, stats.PackagesScanned,
		stats.SitePackagesFound, stats.PythonPackagesScanned,
		stats.ComposerVendorsFound, stats.ComposerPackagesScanned,
		stats.FilesChecked)

	// Surfaced rather than swallowed: a scan that walked past a synced folder
	// without reading any of it must not be mistaken for a scan that read it
	// and found nothing.
	if !stats.Deep {
		fmt.Fprintln(os.Stderr,
			"Note: dependency contents were not broadly scanned; only package checks and targeted application/npm persistence checks ran inside them. Re-run with -deep for dependency content scanning.")
	}

	if stats.FilesUnreadable > 0 {
		fmt.Fprintf(os.Stderr,
			"Note: %d file(s) could not be read and were NOT scanned; see scan-incomplete findings for errors or timeouts.\n",
			stats.FilesUnreadable)
	}
}

func printFindings(findings []Finding, stats ScanStats, coverageDetails bool, invocation string) {
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
		printScanSummary(stats)
		fmt.Println()
		fmt.Println(resultSummary(invocation, findings))
		return
	}

	printScanSummary(stats)
	fmt.Fprintln(os.Stderr)

	fmt.Printf("%s\n\n", resultSummary(invocation, findings))

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

func printCoverage(coverage []Finding, details bool) {
	if len(coverage) == 0 {
		return
	}
	fmt.Printf("\nCoverage incomplete: %d path(s) could not be fully checked. These are not attack indicators.\n", len(coverage))
	if !details {
		fmt.Println("Use --coverage-details or -json to inspect the affected paths.")
		return
	}
	for _, f := range coverage {
		fmt.Printf("    %s\n    %s\n\n", f.Path, f.Detail)
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
