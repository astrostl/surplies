package main

import (
	"os"
	"strings"
	"testing"
)

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
				indicators, _ := splitFindings(findings)
				if !strings.HasSuffix(string(data), resultSummary("surplies 0.9.2 -deep", indicators)+"\n") {
					t.Fatalf("summary not last: json=%v cov=%v detected=%v: %s", jsonOutput, details, detected, data)
				}
			}
		}
	}
}
