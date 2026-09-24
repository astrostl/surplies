package scan

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticGroupsExplainEachCauseOnce(t *testing.T) {
	findings := []Finding{
		{Path: "/z/repo", Detail: "Shallow Git repository: local history only."},
		{Path: "/a/repo", Detail: "Shallow Git repository: local history only."},
		{Path: "/z/file", Detail: "open /z/file: permission denied"},
		{Path: "/a/file", Detail: "open /a/file: permission denied"},
		{Path: "/broken", Detail: "missing object abc123"},
	}
	original, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	printDiagnosticGroups(&output, findings)
	want := "    Shallow Git repository: local history only.\n      /a/repo\n      /z/repo\n" +
		"    missing object abc123\n      /broken\n" +
		"    open <path>: permission denied\n      /a/file\n      /z/file\n"
	if output.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", output.String(), want)
	}
	after, err := json.Marshal(findings)
	if err != nil || string(original) != string(after) {
		t.Fatalf("grouping changed JSON records: %s, %v", after, err)
	}
}

func TestCoverageAndScopeRollups(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdout, stderr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	os.Stdout, os.Stderr = output, output
	printCoverage([]Finding{
		{Path: "/b", Detail: "same failure"},
		{Path: "/a", Detail: "same failure"},
		{Path: "/c", Detail: "distinct failure"},
	}, true)
	printScopeNotices([]Finding{
		{Check: "scan-limited", Path: "/shallow/b", Detail: "same scope limit"},
		{Check: "scan-limited", Path: "/shallow/a", Detail: "same scope limit"},
	}, true)
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, part := range []string{
		"other errors — 3 path(s):",
		"    same failure\n      /a\n      /b\n",
		"    distinct failure\n      /c\n",
		"    same scope limit\n      /shallow/a\n      /shallow/b\n",
	} {
		if strings.Count(got, part) != 1 {
			t.Fatalf("expected exactly one %q in:\n%s", part, got)
		}
	}
}

func TestCoverageIsNotAnIndicator(t *testing.T) {
	findings := []Finding{{Check: "scan-incomplete", Severity: SevWarn}, {Check: "payload-signature", Severity: SevCritical}, {Check: "padded-source-file", Severity: SevWarn}}
	indicators, coverage := splitFindings(findings)
	if len(indicators) != 2 || len(coverage) != 1 {
		t.Fatalf("incorrect groups: %v %v", indicators, coverage)
	}
	if len(findings) != 3 {
		t.Fatal("JSON records modified")
	}
}

func TestResultIncludesVersionAndFlags(t *testing.T) {
	label := InvocationLabel("v0.9.2", []string{"-q"})
	if got := ResultSummary(label, nil); got != "surplies 0.9.2 -q : No supply chain attack indicators found." {
		t.Fatal(got)
	}
	// A default run must say so rather than printing a bare version, which is
	// indistinguishable from a label whose flags were dropped in transcription.
	if got := InvocationLabel("v0.9.2", nil); got != "surplies 0.9.2 [no flags]" {
		t.Fatal(got)
	}
	if got := InvocationLabel("v0.9.2", []string{}); got != "surplies 0.9.2 [no flags]" {
		t.Fatal(got)
	}
	label = InvocationLabel("v0.9.2", []string{"-root", "/custom apps", "-q"})
	if label != `surplies 0.9.2 -root "/custom apps" -q` {
		t.Fatal(label)
	}
	if got := ResultSummary("surplies dev", []Finding{{Severity: SevWarn}}); got != "surplies dev : Found 1 indicator(s): 0 critical, 1 warning, 0 info" {
		t.Fatal(got)
	}
}

func TestResultSummaryEndsHumanReport(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		for _, details := range []bool{false, true} {
			for _, detected := range []bool{false, true} {
				findings := []Finding{{Check: "scan-incomplete", Severity: SevWarn, Path: "/unreadable", Detail: "permission denied"}}
				if detected {
					findings = append(findings, Finding{Check: "payload-signature", Severity: SevCritical, Path: "/payload"})
				}
				output, err := os.CreateTemp(t.TempDir(), "output")
				if err != nil {
					t.Fatal(err)
				}
				stdout, stderr := os.Stdout, os.Stderr
				os.Stdout, os.Stderr = output, output
				PrintResults(findings, ScanStats{}, jsonOutput, details, "surplies 0.9.2 -q")
				os.Stdout, os.Stderr = stdout, stderr
				output.Close()
				data, err := os.ReadFile(output.Name())
				if err != nil {
					t.Fatal(err)
				}
				text := string(data)
				if strings.Count(text, "Result:") != 1 || !strings.Contains(text, "Coverage incomplete:") {
					t.Fatalf("missing/duplicate verdict: %s", text)
				}
				if !jsonOutput && strings.Index(text, "Result:") < strings.Index(text, "CHECKS THAT COULD NOT COMPLETE") {
					t.Fatalf("verdict did not end report: %s", text)
				}

			}
		}
	}
}

func TestCoverageCategoriesAndCounts(t *testing.T) {
	s := New(t.TempDir(), false)
	for i := range 13 {
		s.scanError(fmt.Sprintf("/large/%d.js", i), fileSizeError())
	}
	s.scanError("/protected", &os.PathError{Op: "open", Path: "/protected", Err: os.ErrPermission})
	groups := groupCoverage(s.Findings)
	if got := coverageSummary(groups); got != "Coverage incomplete: 13 size limit exceeded, 1 permission denied." {
		t.Fatal(got)
	}
	s.recordTimeout("/cloud/file.js")
	s.recordDataless("/cloud/placeholder.js")
	s.scanError("/missing", os.ErrNotExist)
	groups = groupCoverage(s.Findings)
	if len(groups["timed out"]) != 1 || len(groups["not downloaded"]) != 1 || len(groups["other errors"]) != 1 {
		t.Fatalf("missing failure categories: %+v", groups)
	}
}

func TestScanModeDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	m := RegisterScanModes(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if !m.Deep || !m.Git || !m.Coverage || m.NpmCache || m.Broad || m.BrowserCache || m.Debug {
		t.Fatalf("unexpected defaults: %+v", m)
	}
}

func TestRemovedScanFlags(t *testing.T) {
	for _, name := range []string{"a", "all", "cov", "deep", "git", "all-content", "raw", "raw-cache"} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var output strings.Builder
		fs.SetOutput(&output)
		RegisterScanModes(fs)
		if fs.Lookup(name) != nil {
			t.Fatalf("removed flag %s still registered", name)
		}
		if err := fs.Parse([]string{"-" + name}); err == nil {
			t.Fatalf("removed flag %s accepted", name)
		}
	}
}

func TestScopeLimitsAndFailuresAreDistinct(t *testing.T) {
	limited := Finding{Check: "scan-limited", Severity: SevInfo, Path: "/shallow"}
	failed := Finding{Check: "scan-incomplete", Severity: SevWarn, Path: "/missing"}
	indicators, coverage := splitFindings([]Finding{limited, failed})
	if len(indicators) != 0 || len(coverage) != 1 {
		t.Fatalf("bad groups: %v %v", indicators, coverage)
	}
	if got := ResultSummary("surplies -a", []Finding{limited}); got != "surplies -a : No supply chain attack indicators found in scanned content." {
		t.Fatal(got)
	}
	if got := ResultSummary("surplies -a", []Finding{limited, failed}); got != "surplies -a : No supply chain attack indicators found in scanned content. Coverage was incomplete." {
		t.Fatal(got)
	}
	got := ResultSummary("surplies -a", []Finding{limited, failed, {Check: "git-payload-hash", Severity: SevCritical}})
	if got != "surplies -a : Found 1 indicator(s): 1 critical, 0 warning, 0 info. Coverage was incomplete." {
		t.Fatal(got)
	}
}

// Zero repositories is scope, not a finished Git scan of everything the user
// owns: repositories kept outside the default root need -root to be seen.
func TestZeroGitRepositoriesPointsAtRoot(t *testing.T) {
	var out strings.Builder
	PrintReportSummary(&out, nil, ScanStats{Git: true, HomeRoot: "/home/u"}, "surplies dev")
	if !strings.Contains(out.String(), "Git: 0/0 repositories completed") || !strings.Contains(out.String(), "add -root for any kept outside") {
		t.Fatalf("no -root hint for a zero-repository scan: %s", out.String())
	}
	// The notice has to survive a skim of a long report, and `~` alone does
	// not tell the reader which directory was actually walked.
	if !strings.Contains(out.String(), "*** NO GIT REPOSITORIES WERE SCANNED! ***") {
		t.Fatalf("zero-repository notice is not prominent: %s", out.String())
	}
	if !strings.Contains(out.String(), "(/home/u)") {
		t.Fatalf("home root not expanded: %s", out.String())
	}
	// Under -only home is not a scan root, so naming it would mislead.
	out.Reset()
	PrintReportSummary(&out, nil, ScanStats{Git: true}, "surplies dev")
	if strings.Contains(out.String(), "(") && strings.Contains(out.String(), "outside ~ (") {
		t.Fatalf("expanded a home root that was never scanned: %s", out.String())
	}
	out.Reset()
	PrintReportSummary(&out, nil, ScanStats{Git: true, GitRepositoriesFound: 1, GitRepositoriesScanned: 1}, "surplies dev")
	if strings.Contains(out.String(), "add -root") {
		t.Fatalf("hint shown with repositories found: %s", out.String())
	}
	out.Reset()
	PrintReportSummary(&out, nil, ScanStats{}, "surplies dev")
	if strings.Contains(out.String(), "Git:") {
		t.Fatalf("Git summary printed without a Git scan: %s", out.String())
	}
}

// A run must announce its version and flags up front, with the same label the
// final summary ends with, so a captured log identifies itself from line one.
func TestRunHeaderIncludesVersionAndFlags(t *testing.T) {
	invocation := InvocationLabel("v0.10.4", []string{"-deep", "-root", "/custom apps"})
	var out bytes.Buffer
	s := New("/home/example", false)
	s.Invocation = invocation
	s.ExtraRoots = []string{"/custom apps"}
	temp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.TempRoots = []string{temp}
	s.debug = newScanDebug(&out)
	s.printRunHeader()
	header := out.String()
	first, _, _ := strings.Cut(header, "\n")
	if first != invocation {
		t.Fatalf("first line = %q, want %q", first, invocation)
	}
	if got := ResultSummary(invocation, nil); !strings.HasPrefix(got, invocation+" ") {
		t.Fatalf("summary %q does not carry the same label", got)
	}
	// Every walked directory on one line: home, the requested roots, and the
	// temp directories, which are walked on every run.
	for _, want := range []string{`Scanning directories: /home/example, "/custom apps", ` + temp + "\n", "Platform: "} {
		if !strings.Contains(header, want) {
			t.Fatalf("missing %q in %q", want, header)
		}
	}
	// Quiet, non-debug runs stay silent; the summary still carries the label.
	quiet := New("/home/example", false)
	quiet.Invocation = invocation
	quiet.printRunHeader()
}

// Absent lifecycle targets fire in dozens of packages on a real machine. One
// block per package with its own path list drowns the findings that need a
// reader, so the human report prints the explanation once and counts packages.
func TestAbsentLifecycleTargetsRollUpInHumanReport(t *testing.T) {
	root := t.TempDir()
	var s *Scanner
	for _, pkg := range []string{"a/node_modules/tr46", "b/node_modules/tr46", "b/node_modules/rollup"} {
		dir := filepath.Join(root, pkg)
		name := filepath.Base(pkg)
		writeFixture(t, filepath.Join(dir, "package.json"), `{"name":"`+name+`","scripts":{"prepare":"node absent.js"}}`)
		if s == nil {
			s = New(root, false)
		}
		s.checkPackage(dir, name)
	}
	var out strings.Builder
	PrintHumanReport(&out, s.Findings, ScanStats{}, true, "surplies dev")
	got := out.String()
	if strings.Count(got, "Lifecycle script target not installed") != 1 {
		t.Fatalf("check did not roll up into one block:\n%s", got)
	}
	for _, want := range []string{"(3 location(s))", "- rollup (prepare): 1\n", "- tr46 (prepare): 2\n"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
	// Individual paths belong in the saved report and -json, not in the block.
	if strings.Contains(got, filepath.Join(root, "a")) {
		t.Fatalf("rolled-up block still lists paths:\n%s", got)
	}
	if paths := findingsFor(s, "missing-script-target"); len(paths) != 3 || paths[0].Path == "" {
		t.Fatalf("records lost their paths: %+v", paths)
	}
}

// A scan that could not read most of the repositories it found exits 2, so
// the summary must not report nothing critical, and the totals must be
// visible without adding up the individual failures in a long report.
func TestCriticalGitCoverageIsStatedInTheSummary(t *testing.T) {
	failures := []Finding{{Check: "scan-incomplete", Severity: SevCritical, Path: "git",
		coverageCategory: "Git coverage", Detail: "Git history coverage is unusable"}}
	var out strings.Builder
	PrintReportSummary(&out, failures, ScanStats{Git: true, GitRepositoriesFound: 379, GitRepositoriesScanned: 67}, "surplies dev")
	if !strings.Contains(out.String(), "*** GIT COVERAGE IS UNUSABLE! *** 312 of 379 repositories (82%)") {
		t.Fatalf("unusable Git coverage is not prominent: %s", out.String())
	}
	if !strings.Contains(out.String(), "no critical indicators, but coverage failed critically") {
		t.Fatalf("exit-2 result reported as nothing critical: %s", out.String())
	}
	// A coverage failure is not an attack indicator and must not be counted
	// as one, here or in the rest of the report.
	if strings.Contains(out.String(), "critical indicator(s)") {
		t.Fatalf("coverage counted as an indicator: %s", out.String())
	}
	// Failures under the threshold stay warnings, with no banner.
	out.Reset()
	PrintReportSummary(&out, nil, ScanStats{Git: true, GitRepositoriesFound: 9, GitRepositoriesScanned: 7}, "surplies dev")
	if strings.Contains(out.String(), "GIT COVERAGE IS UNUSABLE") {
		t.Fatalf("ordinary breakage banner-ed: %s", out.String())
	}
}

// A Git phase skipped because reading stopped must say so, not send the
// reader looking for repositories outside the scan roots.
func TestSkippedGitPhaseIsNotReportedAsScope(t *testing.T) {
	s := New(t.TempDir(), false)
	s.Git = true
	s.readsAbandoned = true
	_, stats := s.Run()
	if !stats.GitSkipped {
		t.Fatal("Git phase skipped after the stall budget was not recorded")
	}
	var out bytes.Buffer
	printGitSummary(&out, stats)
	if !strings.Contains(out.String(), "the Git phase was skipped") || strings.Contains(out.String(), "-root") {
		t.Fatalf("skipped Git phase reported as scope: %q", out.String())
	}
}
