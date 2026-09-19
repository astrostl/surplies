package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findingsFor returns the findings whose Check matches name.
func findingsFor(s *Scanner, check string) []Finding {
	var out []Finding
	for _, f := range s.Findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestFakeFontPayload(t *testing.T) {
	dir := t.TempDir()
	fonts := filepath.Join(dir, "site", "public", "fonts")
	os.MkdirAll(fonts, 0755)

	// A fake font: JavaScript with a font's name and extension. Deliberately
	// carries no known signature, so this exercises the magic-number check on
	// its own — that is the property that survives constant rotation.
	os.WriteFile(filepath.Join(fonts, "fa-solid-400.woff2"),
		[]byte(`try{}catch(err){};var a=require("http");a.get("http://example.invalid/x");`), 0644)

	// A real WOFF2 font: correct magic, binary body.
	real := append([]byte("wOF2"), 0x00, 0x01, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x42)
	os.WriteFile(filepath.Join(fonts, "inter-regular.woff2"), real, 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "fake-font-payload")
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 fake-font-payload finding, got %d: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Path, "fa-solid-400.woff2") {
		t.Errorf("flagged the wrong file: %s", hits[0].Path)
	}
}

func TestRealFontNotFlagged(t *testing.T) {
	dir := t.TempDir()
	fonts := filepath.Join(dir, "assets")
	os.MkdirAll(fonts, 0755)

	// One of each container format the check knows about.
	cases := map[string][]byte{
		"a.woff2": []byte("wOF2\x00\x01\x00\x00binary\xff\xfe"),
		"b.woff":  []byte("wOFF\x00\x01\x00\x00binary\xff\xfe"),
		"c.otf":   []byte("OTTO\x00\x04\x00\x60binary\xff\xfe"),
		"d.ttf":   {0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0xff, 0xfe},
	}
	for name, data := range cases {
		os.WriteFile(filepath.Join(fonts, name), data, 0644)
	}

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "fake-font-payload"); len(hits) != 0 {
		t.Errorf("legitimate fonts flagged: %v", hits)
	}
}

func TestMirroredHTMLFontNotFlagged(t *testing.T) {
	// A site mirrored with wget saves the index page under the asset's name
	// when the asset 404s. The file genuinely is not font data, but it is not
	// an indicator of anything either.
	dir := t.TempDir()
	media := filepath.Join(dir, "mirror", "static", "media")
	os.MkdirAll(media, 0755)

	for name, body := range map[string]string{
		"Explorer.17007a59.otf": `<!doctype html><html lang="en"><head><meta charset="utf-8"/></head></html>`,
		"fallback.woff2":        "<html><body>404 Not Found</body></html>",
		"feed.ttf":              `<?xml version="1.0" encoding="UTF-8"?><rss></rss>`,
	} {
		os.WriteFile(filepath.Join(media, name), []byte(body), 0644)
	}

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "fake-font-payload"); len(hits) != 0 {
		t.Errorf("mirrored HTML saved as a font was flagged: %v", hits)
	}
}

func TestPayloadSignatureInConfig(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "myapp")
	os.MkdirAll(proj, 0755)

	// The injection shape: real config, padding, then the loader.
	poisoned := "export default {}" + strings.Repeat(" ", 280) + `;var _0x=("rmcej%otb%",2857687);`
	os.WriteFile(filepath.Join(proj, "postcss.config.mjs"), []byte(poisoned), 0644)

	// A clean config of the same name pattern must not be flagged.
	os.WriteFile(filepath.Join(proj, "tailwind.config.js"),
		[]byte("export default { content: ['./src/**/*.tsx'] };\n"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 payload-signature finding, got %d: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Path, "postcss.config.mjs") {
		t.Errorf("flagged the wrong file: %s", hits[0].Path)
	}
}

func TestPayloadSignatureRotatedVariants(t *testing.T) {
	// Every documented generation of the loader must match, since the campaign
	// has already rotated its constants once and a stale signature list is how
	// a scan reports clean on a live infection.
	variants := map[string]string{
		"march.config.js":  `x;var _$_1e42=function(){};`,
		"april.config.js":  `x;var q="Cot%3t=shtP";`,
		"marker.config.js": `x;global['!']='8-270-2';`,
		"rotmk.config.js":  `x;global['_V']='8-311';`,
		"npmcs.config.cjs": `x;global.i="A8-3292-1";`,
	}

	for name, body := range variants {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, name), []byte(body), 0644)

			s := New(dir, false)
			s.scanProjectDirs()

			if hits := findingsFor(s, "payload-signature"); len(hits) != 1 {
				t.Errorf("variant %s not detected: got %d findings", name, len(hits))
			}
		})
	}
}

func TestPaddedSourceFileWarnsWithoutSignature(t *testing.T) {
	dir := t.TempDir()

	// Padding but no known signature: this is what a rotation past our
	// signature list looks like, so it warns rather than staying silent.
	os.WriteFile(filepath.Join(dir, "vite.config.ts"),
		[]byte("export default {}"+strings.Repeat(" ", 300)+";var unknownLoader=1;"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "padded-source-file")
	if len(hits) != 1 {
		t.Fatalf("want 1 padded-source-file finding, got %d: %v", len(hits), hits)
	}
	if hits[0].Severity != SevWarn {
		t.Errorf("padding-only detection should be WARN, got %v", hits[0].Severity)
	}
}

func TestPaddedSourceFileNotDoubleReported(t *testing.T) {
	dir := t.TempDir()

	// Padding AND a known signature: report the signature (critical), not the
	// heuristic, so one injection produces one finding.
	os.WriteFile(filepath.Join(dir, "next.config.mjs"),
		[]byte("export default {}"+strings.Repeat(" ", 300)+`;var x="rmcej%otb%";`), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "payload-signature"); len(hits) != 1 {
		t.Errorf("want 1 payload-signature finding, got %d", len(hits))
	}
	if hits := findingsFor(s, "padded-source-file"); len(hits) != 0 {
		t.Errorf("padding warning should be suppressed when a signature matched: %v", hits)
	}
}

func TestMaliciousRepoArtifacts(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "repo")
	os.MkdirAll(proj, 0755)

	os.WriteFile(filepath.Join(proj, "temp_auto_push.bat"), []byte("@echo off"), 0644)
	os.WriteFile(filepath.Join(proj, "config.bat"), []byte("@echo off"), 0644)
	os.WriteFile(filepath.Join(proj, "main.inz.cjs"), []byte("require('./x')"), 0644)

	// A legitimate batch file must not be flagged on extension alone.
	os.WriteFile(filepath.Join(proj, "build.bat"), []byte("@echo off"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "malicious-repo-artifact")
	if len(hits) != 3 {
		t.Fatalf("want 3 malicious-repo-artifact findings, got %d: %v", len(hits), hits)
	}
	for _, f := range hits {
		if strings.Contains(f.Path, "build.bat") {
			t.Errorf("legitimate build.bat flagged: %v", f)
		}
	}
}

func TestGitignoreInjection(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "repo")
	os.MkdirAll(proj, 0755)
	os.WriteFile(filepath.Join(proj, ".gitignore"),
		[]byte("node_modules\ndist\nconfig.bat\n"), 0644)

	clean := filepath.Join(dir, "cleanrepo")
	os.MkdirAll(clean, 0755)
	os.WriteFile(filepath.Join(clean, ".gitignore"),
		[]byte("node_modules\n*.log\n"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "gitignore-injection")
	if len(hits) != 1 {
		t.Fatalf("want 1 gitignore-injection finding, got %d: %v", len(hits), hits)
	}
	if strings.Contains(hits[0].Path, "cleanrepo") {
		t.Errorf("clean .gitignore flagged: %v", hits[0])
	}
}

func TestVscodeTasksJSONIsScanned(t *testing.T) {
	// The walk stops descending at `.vscode`, so this guards the explicit
	// same-directory file scan — without it the loader itself is never read.
	dir := t.TempDir()
	vscode := filepath.Join(dir, "proj", ".vscode")
	os.MkdirAll(vscode, 0755)

	tasks := `{"version":"2.0.0","tasks":[{"label":"eslint-check","type":"shell",` +
		`"command":"node ./public/fonts/fa-solid-400.woff2","runOptions":{"runOn":"folderOpen"}}]}` +
		strings.Repeat(" ", 300) + `//global.i="A8-3292-1"`

	os.WriteFile(filepath.Join(vscode, "tasks.json"), []byte(tasks), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 {
		t.Fatalf("want 1 payload-signature finding in .vscode/tasks.json, got %d: %v", len(hits), hits)
	}
}

func TestPatchedNpmCLI(t *testing.T) {
	dir := t.TempDir()
	npmLib := filepath.Join(dir, "node_modules", "npm", "lib")
	os.MkdirAll(npmLib, 0755)

	// ~1 MB overwritten CLI.
	big := make([]byte, NpmCLIMaxNormalBytes+1)
	for i := range big {
		big[i] = ' '
	}
	os.WriteFile(filepath.Join(npmLib, "cli.js"), big, 0644)

	s := New(dir, false)
	s.checkNpmCLI()

	hits := findingsFor(s, "patched-npm-cli")
	if len(hits) != 1 {
		t.Fatalf("want 1 patched-npm-cli finding, got %d: %v", len(hits), hits)
	}
}

func TestGenuineNpmCLINotFlagged(t *testing.T) {
	dir := t.TempDir()
	npmLib := filepath.Join(dir, "node_modules", "npm", "lib")
	os.MkdirAll(npmLib, 0755)

	// The real thing: four lines, a few hundred bytes.
	os.WriteFile(filepath.Join(npmLib, "cli.js"), []byte(
		"const cli = require('../lib/cli.js')\nmodule.exports = cli\n"), 0644)

	s := New(dir, false)
	s.checkNpmCLI()

	if hits := findingsFor(s, "patched-npm-cli"); len(hits) != 0 {
		t.Errorf("genuine npm cli.js flagged: %v", hits)
	}
}

func TestNpmCLISmallButSigned(t *testing.T) {
	dir := t.TempDir()
	npmLib := filepath.Join(dir, "node_modules", "npm", "lib")
	os.MkdirAll(npmLib, 0755)

	// Under the size threshold but carrying a known signature.
	os.WriteFile(filepath.Join(npmLib, "cli.js"),
		[]byte("const cli = require('../lib/cli.js')\n/*"+`global.i="A8-3292-2"`+"*/\n"), 0644)

	s := New(dir, false)
	s.checkNpmCLI()

	if hits := findingsFor(s, "patched-npm-cli"); len(hits) != 1 {
		t.Errorf("signed-but-small npm cli.js not detected: got %d findings", len(hits))
	}
}

func TestPolinRiderNpmVersion(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "proj", "node_modules", "fetch-page-assets")
	os.MkdirAll(pkgDir, 0755)
	// 1.2.14 is live and unflagged on npm — the case exactly.
	writePackageJSON(t, pkgDir, "fetch-page-assets", "1.2.14")

	cleanDir := filepath.Join(dir, "proj", "node_modules", "fetch-page-assets-ok")
	os.MkdirAll(cleanDir, 0755)
	writePackageJSON(t, cleanDir, "fetch-page-assets", "1.2.8")

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "compromised-version")
	if len(hits) != 1 {
		t.Fatalf("want 1 compromised-version finding, got %d: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Detail, "1.2.14") {
		t.Errorf("unexpected detail: %s", hits[0].Detail)
	}
}

func TestPolinRiderSecurityPlaceholderNotFlagged(t *testing.T) {
	// npm publishes `0.0.1-security` as the clean stub after a takedown.
	// Flagging it would report the remediation as the compromise.
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "proj", "node_modules", "tailwind-scrollbar-hider")
	os.MkdirAll(pkgDir, 0755)
	writePackageJSON(t, pkgDir, "tailwind-scrollbar-hider", "0.0.1-security")

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "compromised-version"); len(hits) != 0 {
		t.Errorf("npm security placeholder flagged: %v", hits)
	}
}

func TestPolinRiderPhantomPackage(t *testing.T) {
	dir := t.TempDir()
	pkgDir := filepath.Join(dir, "proj", "node_modules", "tailwindcss-style-animate")
	os.MkdirAll(pkgDir, 0755)
	writePackageJSON(t, pkgDir, "tailwindcss-style-animate", "1.1.6")

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "phantom-dependency"); len(hits) != 1 {
		t.Errorf("PolinRider typosquat not detected as phantom: got %d findings", len(hits))
	}
}

func TestPolinRiderComposerDevBranch(t *testing.T) {
	// Most PolinRider Packagist artifacts are `dev-*` branch refs rather than
	// tagged releases, because the worm force-pushes into tracked branches.
	dir := t.TempDir()
	composerDir := filepath.Join(dir, "php-app", "vendor", "composer")
	os.MkdirAll(composerDir, 0755)

	installed := `{"packages":[` +
		`{"name":"visanduma/nova-two-factor","version":"dev-nova5"},` +
		`{"name":"sevenspan/laravel-chat","version":"1.5.2"},` +
		`{"name":"symfony/console","version":"6.4.0"}]}`
	os.WriteFile(filepath.Join(composerDir, "installed.json"), []byte(installed), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	hits := findingsFor(s, "compromised-composer-version")
	if len(hits) != 2 {
		t.Fatalf("want 2 composer findings, got %d: %v", len(hits), hits)
	}
	for _, f := range hits {
		if strings.Contains(f.Detail, "symfony/console") {
			t.Errorf("clean package flagged: %v", f)
		}
	}
}

func TestPolinRiderPythonVersion(t *testing.T) {
	dir := t.TempDir()
	sp := filepath.Join(dir, "venv", "lib", "python3.12", "site-packages")
	os.MkdirAll(filepath.Join(sp, "pybitjs-0.1.0.dist-info"), 0755)
	os.MkdirAll(filepath.Join(sp, "requests-2.31.0.dist-info"), 0755)

	s := New(dir, false)
	s.scanPythonPackages()

	hits := findingsFor(s, "compromised-python-version")
	if len(hits) != 1 {
		t.Fatalf("want 1 compromised-python-version finding, got %d: %v", len(hits), hits)
	}
	if !strings.Contains(hits[0].Detail, "pybitjs") {
		t.Errorf("unexpected detail: %s", hits[0].Detail)
	}
}

func TestCleanProjectNoContentFindings(t *testing.T) {
	// A realistic clean project: build configs, a real font, a normal
	// .gitignore, a legitimate folderOpen task. None of it may be flagged.
	dir := t.TempDir()
	proj := filepath.Join(dir, "webapp")
	os.MkdirAll(filepath.Join(proj, "public", "fonts"), 0755)
	os.MkdirAll(filepath.Join(proj, ".vscode"), 0755)

	os.WriteFile(filepath.Join(proj, "vite.config.ts"),
		[]byte("import {defineConfig} from 'vite';\nexport default defineConfig({});\n"), 0644)
	os.WriteFile(filepath.Join(proj, "tailwind.config.js"),
		[]byte("module.exports = { content: [] };\n"), 0644)
	os.WriteFile(filepath.Join(proj, "index.js"),
		[]byte("console.log('hi');\n"), 0644)
	os.WriteFile(filepath.Join(proj, ".gitignore"),
		[]byte("node_modules\ndist\n.env\n"), 0644)
	os.WriteFile(filepath.Join(proj, "public", "fonts", "inter.woff2"),
		append([]byte("wOF2"), 0x00, 0x01, 0x00, 0x00, 0xde, 0xad), 0644)
	os.WriteFile(filepath.Join(proj, ".vscode", "tasks.json"),
		[]byte(`{"version":"2.0.0","tasks":[{"label":"watch","type":"npm","script":"dev","runOptions":{"runOn":"folderOpen"}}]}`), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	for _, check := range []string{
		"fake-font-payload", "payload-signature", "padded-source-file",
		"malicious-repo-artifact", "gitignore-injection",
	} {
		if hits := findingsFor(s, check); len(hits) != 0 {
			t.Errorf("clean project produced %s findings: %v", check, hits)
		}
	}
}
