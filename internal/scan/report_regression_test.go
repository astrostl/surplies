package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeLabelDoesNotRewriteWords(t *testing.T) {
	var out bytes.Buffer
	printDiagnosticGroups(&out, []Finding{{Path: "content", Detail: "Ordinary content reads; use -broad"}})
	if strings.Contains(out.String(), "<path>") {
		t.Fatal(out.String())
	}
}
func TestNativeEntrypointExcludedBeforeTextSizeLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "native.node")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte{0xcf, 0xfa, 0xed, 0xfe}); err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(SignatureScanMaxBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	s := New(root, false)
	s.inspectDependencyTarget(root, "native.node")
	if n := s.contentIO.bytes.Load(); n != 32 {
		t.Fatalf("native read %d bytes", n)
	}
	if len(findingsFor(s, "scan-incomplete")) != 0 || s.contentIO.binary.Load() != 1 {
		t.Fatalf("native scope misreported: %+v %v", s.stats, s.Findings)
	}
	writeFixture(t, filepath.Join(root, "script.node"), "/*RS260605*/")
	s.inspectDependencyTarget(root, "script.node")
	if len(findingsFor(s, "payload-signature")) != 1 {
		t.Fatal("renamed script was excluded by extension")
	}
}

// A lifecycle target that is not on disk is upstream packaging, not a read
// surplies failed: build hooks are stripped from published tarballs and pruned
// installs drop install helpers, so both must report the same way, and must do
// so outside node_modules too (renamed dependency directories are common).
func TestAbsentLifecycleTargetIsNotAReadFailure(t *testing.T) {
	for _, hook := range []string{"prepare", "prepack", "postinstall", "install"} {
		for _, dir := range []string{"node_modules", "node_noodles"} {
			root := t.TempDir()
			pkg := filepath.Join(root, dir, "pkg")
			writeFixture(t, filepath.Join(pkg, "package.json"), `{"name":"pkg","scripts":{"`+hook+`":"node absent.js"}}`)
			s := New(root, false)
			s.checkPackage(pkg, "pkg")
			missing := findingsFor(s, "missing-script-target")
			if len(missing) != 1 || len(findingsFor(s, "scan-incomplete")) != 0 || len(findingsFor(s, "scan-limited")) != 0 {
				t.Fatalf("%s in %s: %+v", hook, dir, s.Findings)
			}
			if missing[0].Severity != SevInfo || !strings.Contains(missing[0].Detail, hook+" script") {
				t.Fatalf("%s in %s: %+v", hook, dir, missing[0])
			}
		}
	}
}
func TestNonNpmUpdateManifest(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "package.json"), `{"version":281,"url":"https://example.invalid/update","files":[{"name":"data.json","version":281}]}`)
	s := New(root, false)
	s.Deep = true
	s.checkPackageManifest(root, "updates", false)
	if len(findingsFor(s, "scan-incomplete")) != 0 || len(findingsFor(s, "scan-limited")) != 1 {
		t.Fatal(s.Findings)
	}
}

func TestHumanReportHasOneVerdictAndGroupsRelatedWarnings(t *testing.T) {
	var out bytes.Buffer
	findings := []Finding{
		{Check: "workspace-setting-context", Severity: SevInfo, Path: "/settings", Detail: "automatic tasks enabled"},
		{Check: "suspicious-source-execution", Severity: SevWarn, Path: "/one", Detail: "review this pattern"},
		{Check: "suspicious-source-execution", Severity: SevWarn, Path: "/two", Detail: "review this pattern"},
		{Check: "scan-incomplete", Severity: SevWarn, Path: "/blocked", Detail: "permission denied", coverageCategory: "permission denied"},
		{Check: "scan-limited", Severity: SevInfo, Path: "/cache", Detail: "cache excluded"},
	}
	PrintHumanReport(&out, findings, ScanStats{}, true, "surplies -a")
	text := out.String()
	if !strings.Contains(text, "no critical indicators; 2 warning(s) need review") {
		t.Fatal(text)
	}
	if strings.Count(text, "review this pattern") != 1 || strings.Count(text, "Result:") != 1 {
		t.Fatal(text)
	}
	last := -1
	for _, heading := range []string{"WARNINGS TO REVIEW", "INFORMATIONAL CONTEXT", "CHECKS THAT COULD NOT COMPLETE", "SCOPE LIMITS", "Result:"} {
		pos := strings.Index(text, heading)
		if pos <= last {
			t.Fatalf("wrong report order: %s", text)
		}
		last = pos
	}
	for _, path := range []string{"/settings", "/one", "/two", "/blocked"} {
		if !strings.Contains(text, path) {
			t.Fatalf("lost %s", path)
		}
	}
}

func TestScopePathsStayInSavedReportNotTerminal(t *testing.T) {
	var findings []Finding
	for i := range 100 {
		findings = append(findings, Finding{Check: "scan-limited", Severity: SevInfo, Path: fmt.Sprintf("/cache/location-%d", i), Detail: "Browser cache storage excluded from traversal"})
	}
	var out bytes.Buffer
	PrintHumanReport(&out, findings, ScanStats{}, true, "surplies -a")
	if strings.Contains(out.String(), "/cache/location-") || strings.Count(out.String(), "\n") > 20 {
		t.Fatalf("scope path dump returned: %s", out.String())
	}
	if !strings.Contains(out.String(), "Browser cache directories excluded: 100 notice(s)") {
		t.Fatal(out.String())
	}
	path, err := SaveScanReport(t.TempDir(), findings, ScanStats{}, "surplies -a", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Findings []struct {
			Check    string `json:"check"`
			Severity string `json:"severity"`
			Path     string `json:"path"`
			Detail   string `json:"detail"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 100 || report.Findings[99].Path != "/cache/location-99" {
		t.Fatal("full diagnostics lost")
	}
	for i, got := range report.Findings {
		want := findings[i]
		if got.Check != want.Check || got.Severity != want.Severity.String() || got.Path != want.Path || got.Detail != want.Detail {
			t.Fatalf("finding %d changed in saved report: %+v", i, got)
		}
	}
}
