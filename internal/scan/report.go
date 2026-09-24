package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

func PrintReportSummary(out io.Writer, findings []Finding, stats ScanStats, invocation string) {
	critical, warnings, context, criticalCoverage := 0, 0, 0, 0
	_, coverage := splitFindings(findings)
	for _, f := range findings {
		if isCoverageCheck(f.Check) || f.Check == "scan-limited" {
			if isCoverageCheck(f.Check) && f.Severity == SevCritical {
				criticalCoverage++
			}
			continue
		}
		switch f.Severity {
		case SevCritical:
			critical++
		case SevWarn:
			warnings++
		default:
			context++
		}
	}
	fmt.Fprintf(out, "\n%s\n", invocation)
	switch {
	case critical > 0:
		fmt.Fprintf(out, "Result: %d critical indicator(s); %d warning(s) need review.\n", critical, warnings)
	case criticalCoverage > 0:
		// A coverage failure is not an indicator, and counting it as one
		// would say this machine shows signs of an attack. It still exits 2,
		// so the line has to say why rather than reporting nothing critical.
		fmt.Fprintf(out, "Result: no critical indicators, but coverage failed critically and the scan cannot be trusted; %d warning(s) need review.\n", warnings)
	default:
		fmt.Fprintf(out, "Result: no critical indicators; %d warning(s) need review.\n", warnings)
	}
	if len(coverage) > 0 {
		fmt.Fprintln(out, coverageSummary(groupCoverage(coverage)))
	} else {
		fmt.Fprintln(out, "Coverage: selected checks completed; scope limits apply.")
	}
	fmt.Fprintf(out, "Run: %s | %.2f MiB content read | %d files checked | %d binary files skipped\n", stats.Duration.Round(time.Millisecond), float64(stats.ContentBytesRead)/(1<<20), stats.FilesChecked, stats.BinaryPrefixesSkipped)
	fmt.Fprintln(out, "Read count excludes filesystem metadata and Git subprocess I/O.")
	if d := stats.Debug; d != nil {
		if d.ScannerDiskIO.Available {
			fmt.Fprintf(out, "OS disk reads: scanner %.2f MiB; measured Git children %.2f MiB (%d/%d commands).\n", float64(d.ScannerDiskIO.ReadBytes)/(1<<20), float64(d.GitDiskReadBytes)/(1<<20), d.GitDiskCommandsMeasured, d.GitDiskCommandsMeasured+d.GitDiskCommandsUnmeasured)
		} else {
			fmt.Fprintf(out, "OS disk reads unavailable: %s\n", d.ScannerDiskIO.Error)
		}
	}
	printGitSummary(out, stats)
	if context > 0 {
		fmt.Fprintf(out, "Context: %d informational observation(s), not attack indicators.\n", context)
	}
}

func gitVersionLabel(version string) string {
	if version == "" {
		return "unknown"
	}
	return version
}

// The Git counts and the banners that qualify them. Split out of
// PrintReportSummary so the summary stays a summary.
func printGitSummary(out io.Writer, stats ScanStats) {
	if !stats.Git {
		return
	}
	// A skipped phase found nothing because it never looked; the counts and
	// the -root advice below would both describe a scan that did not happen.
	if stats.GitSkipped {
		fmt.Fprint(out, "\n*** GIT HISTORY WAS NOT SCANNED! *** the scan stopped reading after repeated timeouts, so the Git phase was skipped\n")
		return
	}
	// The resolved binary and its version, on every run: which Git a scan
	// found is the difference between a Git half that ran and one that could
	// not start, and PATH differs between an interactive shell and a root
	// daemon on the same machine.
	if stats.GitPath != "" {
		fmt.Fprintf(out, "Git binary: %s (version %s)\n", stats.GitPath, gitVersionLabel(stats.GitVersion))
	}
	fmt.Fprintf(out, "Git: %d/%d repositories completed; %d blobs considered, %d candidate blobs hashed, %d matched by object identity, %d inspected by name.\n", stats.GitRepositoriesScanned, stats.GitRepositoriesFound, stats.GitBlobsConsidered, stats.GitBlobsChecked, stats.GitBlobsIdentified, stats.GitBlobsInspected)
	// An older Git still runs the size-matched history scan, so the line above
	// is real coverage -- but the filename-gated checks it did not run are the
	// ones that find the config-append landing. Say which half was missing
	// rather than letting the counts imply a whole history scan.
	if stats.GitRepositoriesFound > 0 && stats.GitVersion != "" && !gitPathsSupported(stats.GitVersion) {
		if old, _ := gitTooOld(stats.GitVersion); !old {
			fmt.Fprintf(out, "Git history covered payload sizes and object identities only: %s cannot emit object paths (needs %d.%d), so the filename-gated history checks did not run.\n",
				stats.GitVersion, GitObjectPathsVersion[0], GitObjectPathsVersion[1])
		}
	}
	if old, _ := gitTooOld(stats.GitVersion); old && stats.GitRepositoriesFound > 0 {
		fmt.Fprintf(out, "\n*** GIT IS TOO OLD TO INSPECT REPOSITORIES! *** %s is %s; %d.%d or newer is required, so this report covers files only\n",
			stats.GitPath, stats.GitVersion, MinimumGitVersion[0], MinimumGitVersion[1])
	}
	if unscannable := stats.GitRepositoriesFound - stats.GitRepositoriesScanned; unscannable*100 > stats.GitRepositoriesFound*GitUnscannableCriticalPercent {
		// The per-repository failures are already listed, but a reader
		// skimming a long report cannot add them up against the total.
		fmt.Fprintf(out, "\n*** GIT COVERAGE IS UNUSABLE! *** %d of %d repositories (%d%%) could not be scanned; failures are listed above\n",
			unscannable, stats.GitRepositoriesFound, GitUnscannablePercent(stats.GitRepositoriesFound, stats.GitRepositoriesScanned))
	}
	if stats.GitRepositoriesFound != 0 {
		return
	}
	// Zero is scope, not a failed Git scan: repositories kept outside the
	// default root are invisible until -root names them.
	// Under -only home was never walked, so advice about what lies
	// outside it describes a scan that did not happen.
	if stats.HomeRoot == "" {
		fmt.Fprint(out, "\n*** NO GIT REPOSITORIES WERE SCANNED! *** none found under the -root path(s) given\n")
		return
	}
	fmt.Fprintf(out, "\n*** NO GIT REPOSITORIES WERE SCANNED! *** add -root for any kept outside %s (%s)\n",
		homeLabel(runtime.GOOS), stats.HomeRoot)
}

func PrintHumanReport(out io.Writer, findings []Finding, stats ScanStats, details bool, invocation string) {
	defer PrintReportSummary(out, findings, stats, invocation)
	for _, section := range []struct {
		severity Severity
		title    string
	}{{SevCritical, "CRITICAL INDICATORS"}, {SevWarn, "WARNINGS TO REVIEW — heuristics, not proof of compromise"}, {SevInfo, "INFORMATIONAL CONTEXT"}} {
		var selected []Finding
		for _, f := range findings {
			if !isCoverageCheck(f.Check) && f.Check != "scan-limited" && f.Severity == section.severity {
				selected = append(selected, f)
			}
		}
		if len(selected) == 0 {
			continue
		}
		fmt.Fprintf(out, "\n%s (%d)\n", section.title, len(selected))
		groups, keys := groupIndicators(selected)
		for _, key := range keys {
			group := groups[key]
			if group[0].rollup != "" {
				printRollupGroup(out, group)
				continue
			}
			printIndicatorGroup(out, group)
		}
	}
	printReportDiagnostics(out, findings, details)
}

// groupIndicators collects findings that share an explanation, in first-seen
// order of the sorted key. A finding carrying per-location evidence groups on
// its cause instead of its whole detail, so one explanation is not printed once
// per blob; see the cause field on Finding.
func groupIndicators(selected []Finding) (map[string][]Finding, []string) {
	groups := make(map[string][]Finding)
	var keys []string
	for _, f := range selected {
		key := f.Check + "\x00" + f.Detail
		if f.cause != "" {
			key = f.Check + "\x00" + f.cause
		}
		if f.rollup != "" {
			key = f.Check
		}
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], f)
	}
	sort.Strings(keys)
	return groups, keys
}

// printIndicatorGroup prints one shared explanation followed by its paths, each
// with whatever evidence belongs to that path alone.
func printIndicatorGroup(out io.Writer, group []Finding) {
	shared := group[0].Detail
	if group[0].cause != "" {
		shared = group[0].cause
	}
	fmt.Fprintf(out, "\n  %s (%d location(s))\n    %s\n", reportCheckTitle(group[0].Check), len(group), shared)
	lines := make([]string, 0, len(group))
	for _, f := range group {
		line := f.Path
		if f.evidence != "" {
			line += "\n        " + f.evidence
		}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	for _, line := range lines {
		fmt.Fprintf(out, "    - %s\n", line)
	}
}

// Some checks describe ordinary ecosystem shape rather than anything to look
// at, and fire in dozens of packages at once. Printing each package as its own
// block with its own path list buries the findings that need a reader. Print
// the shared explanation once and count the subjects; the saved report and
// -json keep every path.
func printRollupGroup(out io.Writer, group []Finding) {
	fmt.Fprintf(out, "\n  %s (%d location(s))\n    %s\n", reportCheckTitle(group[0].Check), len(group), rollupDetail(group[0].Check))
	counts := map[string]int{}
	for _, f := range group {
		counts[f.rollup]++
	}
	labels := make([]string, 0, len(counts))
	for label := range counts {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Fprintf(out, "    - %s: %d\n", label, counts[label])
	}
}

func rollupDetail(check string) string {
	switch check {
	case "missing-script-target":
		return "Packages declaring a lifecycle script whose target file is not installed. Published tarballs routinely strip build hooks, so this is upstream packaging, not a scan failure. Paths in the saved report."
	default:
		return reportCheckTitle(check)
	}
}

func reportCheckTitle(check string) string {
	switch check {
	case "suspicious-source-execution":
		return "Suspicious execution patterns"
	case "loader-structure":
		return "Local module loader pattern"
	case "unicode-concealment":
		return "Potentially concealed Unicode"
	case "workspace-setting-context":
		return "Workspace settings"
	case "missing-script-target":
		return "Lifecycle script target not installed"
	default:
		return strings.ReplaceAll(check, "-", " ")
	}
}

func scopeReportCategory(f Finding) string {
	switch {
	case strings.HasPrefix(f.Detail, "Browser cache"):
		return "Browser cache directories excluded"
	case strings.HasPrefix(f.Detail, "Raw npm"):
		return "Raw npm cache directories excluded"
	case strings.HasPrefix(f.Detail, "DNS completed"):
		return "Domains without routable DNS answers"
	case strings.HasPrefix(f.Detail, "Shallow Git"):
		return "Shallow Git repositories"
	case strings.HasPrefix(f.Detail, "Binary plist"):
		return "Binary startup plists not decoded"
	case strings.HasPrefix(f.Detail, "Directory link"):
		return "Directory links not followed"
	case strings.HasPrefix(f.Detail, "Non-npm"):
		return "Non-npm manifests"
	case strings.HasPrefix(f.Detail, "Temp directories"):
		return "Temp directories not walked"
	case f.Detail == binaryExcludedDetail:
		return "Binary files excluded from text inspection"
	case f.Path == "content" || f.Path == "dependencies":
		return "Files not read unless a check selects them"
	default:
		return "Other scope limits"
	}
}

// Preserve every diagnostic from this run without requiring another scan.
// CreateTemp uses a private 0600 file; reports contain paths and findings, not
// inspected source contents. JSON stdout mode already preserves these records.
// summary is the human-readable block this run printed to the terminal. It is
// stored verbatim so the report is self-contained: whoever ends up reading the
// file -- an MDM inventory record, a ticket attachment, a colleague -- gets the
// same plain-language verdict and the loud coverage banners, not just the
// structured findings they would have to re-derive. Pass "" to omit it.
func SaveScanReport(dir string, findings []Finding, stats ScanStats, invocation, summary string) (string, error) {
	f, err := os.CreateTemp(dir, "surplies-report-*.json")
	if err != nil {
		return "", err
	}
	// Reproduce the terminal output verbatim: everything the run printed after
	// the separator rule, starting with the saved-report path. Only this
	// function knows that path, so it prepends the line rather than making the
	// caller guess a filename it has not been given yet.
	if summary != "" {
		summary = fmt.Sprintf("\n\nFull report saved: %s\n%s", f.Name(), summary)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	// Summary goes LAST. It is many lines of prose, and putting it ahead of the
	// structured fields pushes stats and findings off the first screen of
	// anyone reading the raw file.
	err = enc.Encode(struct {
		Invocation string    `json:"invocation"`
		Stats      ScanStats `json:"stats"`
		Findings   []Finding `json:"findings"`
		Summary    string    `json:"summary,omitempty"`
	}{invocation, stats, findings, summary})
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func printReportDiagnostics(out io.Writer, findings []Finding, details bool) {
	_, coverage := splitFindings(findings)
	if len(coverage) > 0 && details {
		fmt.Fprintln(out, "\nCHECKS THAT COULD NOT COMPLETE — coverage gaps, not attack indicators")
		groups := groupCoverage(coverage)
		for _, category := range coverageCategories {
			if group := groups[category]; len(group) > 0 {
				fmt.Fprintf(out, "\n  %s (%d location(s))\n", category, len(group))
				printDiagnosticGroups(out, group)
			}
		}
	}
	var limits []Finding
	for _, f := range findings {
		if f.Check == "scan-limited" {
			limits = append(limits, f)
		}
	}
	if len(limits) > 0 && details {
		fmt.Fprintln(out, "\nSCOPE LIMITS (details in saved report)")
		counts := map[string]int{}
		for _, f := range limits {
			counts[scopeReportCategory(f)]++
		}
		keys := make([]string, 0, len(counts))
		for key := range counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(out, "  %s: %d notice(s)\n", key, counts[key])
		}
	}

	if len(coverage) > 0 && !details {
		fmt.Fprintln(out, "\nUse -json for full coverage records.")
	}
}
