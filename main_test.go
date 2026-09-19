package main

import (
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
	label := invocationLabel("v0.9.2", []string{"-deep"})
	if got := resultSummary(label, nil); got != "surplies 0.9.2 -deep : No supply chain attack indicators found." {
		t.Fatal(got)
	}
	label = invocationLabel("v0.9.2", []string{"-root", "/custom apps", "-q"})
	if label != `surplies 0.9.2 -root "/custom apps" -q` {
		t.Fatal(label)
	}
	if got := resultSummary("surplies dev", []Finding{{Severity: SevWarn}}); got != "surplies dev : Found 1 indicator(s): 0 critical, 1 warning, 0 info" {
		t.Fatal(got)
	}
}

func TestResultSummaryIsLast(t *testing.T) {
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
				printResults(findings, ScanStats{}, jsonOutput, details, "surplies 0.9.2 -deep")
				os.Stdout, os.Stderr = stdout, stderr
				output.Close()
				data, err := os.ReadFile(output.Name())
				if err != nil {
					t.Fatal(err)
				}
				footer := "Scan complete in 0s\nStats: 0 node_modules (0 pkgs), 0 site-packages (0 pkgs), 0 composer vendors (0 pkgs), 0 files checked\n\n" + resultSummary("surplies 0.9.2 -deep", findings) + "\n"
				if !strings.HasSuffix(string(data), footer) {
					t.Fatalf("summary not last: json=%v cov=%v detected=%v: %s", jsonOutput, details, detected, data)
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

func TestScanModeFlags(t *testing.T) {
	for _, args := range [][]string{{"-a"}, {"-all"}, {"-cov", "-deep", "-git"}, {"-a", "-git=false"}} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		m := registerScanModes(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		m.expand()
		if !m.Deep || !m.Git || !m.Coverage {
			t.Fatalf("%v: %+v", args, m)
		}
	}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	m := registerScanModes(fs)
	if err := fs.Parse([]string{"-deep"}); err != nil {
		t.Fatal(err)
	}
	m.expand()
	if m.Git || m.Coverage {
		t.Fatalf("deep unexpectedly enables git/coverage: %+v", m)
	}
}

func TestAllAliasHiddenFromUsage(t *testing.T) {
	previous := flag.CommandLine
	defer func() { flag.CommandLine = previous }()
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	registerScanModes(flag.CommandLine)
	var output strings.Builder
	flag.CommandLine.SetOutput(&output)
	printUsage()
	text := output.String()
	if strings.Contains(text, "  -all\n") || !strings.Contains(text, "  -a\n") || !strings.Contains(text, "  -git\n") {
		t.Fatal(text)
	}
}

func TestScopeLimitsAndFailuresAreDistinct(t *testing.T) {
	limited := Finding{Check: "scan-limited", Severity: SevInfo, Path: "/shallow"}
	failed := Finding{Check: "scan-incomplete", Severity: SevWarn, Path: "/missing"}
	indicators, coverage := splitFindings([]Finding{limited, failed})
	if len(indicators) != 0 || len(coverage) != 1 {
		t.Fatalf("bad groups: %v %v", indicators, coverage)
	}
	if got := resultSummary("surplies -a", []Finding{limited}); got != "surplies -a : No supply chain attack indicators found in scanned content." {
		t.Fatal(got)
	}
	if got := resultSummary("surplies -a", []Finding{limited, failed}); got != "surplies -a : No supply chain attack indicators found in scanned content. Coverage was incomplete." {
		t.Fatal(got)
	}
	got := resultSummary("surplies -a", []Finding{limited, failed, {Check: "git-payload-hash", Severity: SevCritical}})
	if got != "surplies -a : Found 1 indicator(s): 1 critical, 0 warning, 0 info. Coverage was incomplete." {
		t.Fatal(got)
	}
}
