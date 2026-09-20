package scan

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
	s.recordStall("/cloud", "/cloud/file.js")
	s.scanError("/missing", os.ErrNotExist)
	groups = groupCoverage(s.Findings)
	if len(groups["timed out"]) != 1 || len(groups["other errors"]) != 1 {
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
	for _, want := range []string{"Scanning home directory: /home/example", "Additional scan root: /custom apps", "Platform: "} {
		if !strings.Contains(header, want) {
			t.Fatalf("missing %q in %q", want, header)
		}
	}
	// Quiet, non-debug runs stay silent; the summary still carries the label.
	quiet := New("/home/example", false)
	quiet.Invocation = invocation
	quiet.printRunHeader()
}
