package scan

// Human-readable result rendering. Kept beside report.go so the CLI stays a
// thin flag parser and the scanner owns how its own findings are presented.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

func PrintResults(findings []Finding, stats ScanStats, jsonOutput, coverageDetails bool, invocation string) {
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
		if stats.Debug != nil && stats.Debug.DebugLog != "" {
			fmt.Fprintf(os.Stderr, "Debug log saved: %s\n", stats.Debug.DebugLog)
		}
		PrintReportSummary(os.Stderr, findings, stats, invocation)
	} else {
		if path, err := SaveScanReport("", findings, stats, invocation); err == nil {
			fmt.Fprintf(os.Stdout, "\n-----------------------------------------------------------------------------\n\nFull report saved: %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "Could not save full report: %v\n", err)
			printDiagnosticGroups(os.Stdout, findings)
		}
		if stats.Debug != nil && stats.Debug.DebugLog != "" {
			fmt.Fprintf(os.Stdout, "Debug log saved: %s\n", stats.Debug.DebugLog)
		}
		PrintHumanReport(os.Stdout, findings, stats, coverageDetails, invocation)
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

func ResultSummary(invocation string, findings []Finding) string {
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

func InvocationLabel(buildVersion string, args []string) string {
	parts := []string{"surplies", strings.TrimPrefix(buildVersion, "v")}
	// A bare version reads the same whether the run was a default scan or had
	// its flags lost in transcription. Saying so makes a pasted log explicit
	// about which one it was.
	if len(args) == 0 {
		return strings.Join(append(parts, "[no flags]"), " ")
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\r\n\"\\") || arg == "" {
			arg = strconv.Quote(arg)
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}
