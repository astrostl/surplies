package main

import "testing"

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
	label = invocationLabel("v0.9.2", []string{"--persistence-root", "/custom apps", "-q"})
	if label != `surplies 0.9.2 --persistence-root "/custom apps" -q` {
		t.Fatal(label)
	}
	if got := resultSummary("surplies dev", []Finding{{Severity: SevWarn}}); got != "surplies dev : Found 1 indicator(s): 0 critical, 1 warning, 0 info" {
		t.Fatal(got)
	}
}
