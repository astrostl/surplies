package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationPersistenceOutsideHomeAndDependencies(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	app := filepath.Join(root, "Applications", "Code.app", "Contents", "Resources", "app")
	entry := filepath.Join(app, "node_modules", "@vscode", "deviceid", "dist", "index.js")
	sidecar := filepath.Join(filepath.Dir(entry), "index.inz.cjs")
	writeFixture(t, entry, `require('./index.inz.cjs')`)
	writeFixture(t, sidecar, "// inert fixture")
	writeFixture(t, filepath.Join(app, "out", "main.js"), "/*M260630A*/ // inert fixture")
	s := New(home, false)
	patterns := []string{entry, filepath.Join(app, "out", "main.js"), entry}
	s.checkApplicationPatterns(patterns)
	if len(findingsFor(s, "patched-application")) != 2 || len(findingsFor(s, "malicious-repo-artifact")) != 1 {
		t.Fatalf("missing or duplicate findings: %+v", s.Findings)
	}
}

func TestApplicationOrphanSidecarAndCleanEntrypoint(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "main.inz.orig"), "// backup")
	writeFixture(t, filepath.Join(dir, "index.js"), `module.exports = {version: 1}`)
	s := New(dir, false)
	s.checkApplicationPatterns([]string{filepath.Join(dir, "main.js"), filepath.Join(dir, "index.js")})
	s.scanProjectDirs()
	if len(s.Findings) != 1 || s.Findings[0].Check != "malicious-repo-artifact" {
		t.Fatalf("orphan sidecar should be detected once: %+v", s.Findings)
	}
}

func TestSmallNpmSidecarStub(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "node_modules", "npm", "lib", "cli.js")
	writeFixture(t, entry, `require('./cli.inz.cjs')`)
	writeFixture(t, filepath.Join(filepath.Dir(entry), "cli.inz.cjs"), "// inert")
	s := New(dir, false)
	s.checkNpmCLI()
	if len(findingsFor(s, "patched-npm-cli")) != 1 || len(findingsFor(s, "malicious-repo-artifact")) != 1 {
		t.Fatalf("small stub and sidecar not detected: %+v", s.Findings)
	}
}

func TestNpmSidecarWithoutEntrypoint(t *testing.T) {
	dir := t.TempDir()
	sidecar := filepath.Join(dir, "node_modules", "npm", "lib", "cli.inz.cjs")
	writeFixture(t, sidecar, "// inert")
	s := New(dir, false)
	s.checkNpmCLI()
	if len(findingsFor(s, "malicious-repo-artifact")) != 1 {
		t.Fatalf("orphan npm sidecar missed: %+v", s.Findings)
	}
}

func TestApplicationReadFailureIsNotClean(t *testing.T) {
	dir := t.TempDir()
	// A directory in place of the entrypoint cannot be inspected as source.
	path := filepath.Join(dir, "main.js")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	s := New(dir, false)
	s.checkApplicationPatterns([]string{path})
	if len(findingsFor(s, "scan-incomplete")) != 1 {
		t.Fatalf("unreadable entrypoint reported clean: %+v", s.Findings)
	}
}

func TestPublishedPersistenceMarkers(t *testing.T) {
	for _, marker := range []string{"/*RS260605*/", "/*C250617A*/", "/*C250618A*/", "/*C250619A*/", "/*C250620A*/", "/*C260511A*/", "/*C260512A*/", "/*M260630A*/", "__inzCR", "X-Payload-B64", "y-p_>d$0B&@^1aQk", "ThZG+0jfXE6VAGOJ", "/0x/js", "/0x/clb"} {
		t.Run(marker, func(t *testing.T) {
			if _, ok := payloadSignature([]byte(marker)); !ok {
				t.Fatalf("missing %q", marker)
			}
		})
	}
	for _, benign := range []string{"/*M123456A*/", "/*C260901A*/", "require('./legitimate.cjs')", "const url = '/u/f';"} {
		if _, ok := persistenceSignature([]byte(benign)); ok {
			t.Fatalf("overbroad signature: %q", benign)
		}
	}
	if _, ok := payloadSignature([]byte(`require('socket.io-client'); const upload = '/u/f';`)); !ok {
		t.Fatal("corroborated upload/client combination missed")
	}
}

func TestPersistenceInstallLayouts(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			patterns := ApplicationEntrypointGlobs(dir, goos, func(string) string { return "" })
			var homeDeviceID, discord string
			for _, p := range patterns {
				if !strings.HasPrefix(p, dir) {
					continue
				}
				if strings.Contains(p, "deviceid") {
					homeDeviceID = p
				}
				if strings.Contains(p, "discord_desktop_core") {
					discord = strings.ReplaceAll(p, "*", "1")
				}
			}
			if homeDeviceID == "" || discord == "" {
				t.Fatalf("missing layouts: %v", patterns)
			}
			writeFixture(t, homeDeviceID, "/*RS260605*/")
			writeFixture(t, discord, "/*C260511A*/")
			// Discord profiles also contain ordinary files beside version dirs.
			for _, p := range patterns {
				if strings.HasPrefix(p, dir) && strings.Contains(p, "discord*") {
					root := strings.Split(p, "discord*")[0] + "discord1"
					writeFixture(t, filepath.Join(root, "Preferences"), "{}")
				}
			}
			s := New(dir, false)
			// Avoid touching the test runner's actual application directories.
			var local []string
			for _, p := range patterns {
				if strings.HasPrefix(p, dir) {
					local = append(local, p)
				}
			}
			s.checkApplicationPatterns(local)
			if len(findingsFor(s, "patched-application")) != 2 {
				t.Fatalf("layout missed: %+v", s.Findings)
			}
			if len(findingsFor(s, "scan-incomplete")) != 0 {
				t.Fatalf("ordinary profile file treated as directory: %+v", s.Findings)
			}
		})
	}
}

func TestStagingIsWarningAndDeduplicated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "get-pip.py")
	writeFixture(t, path, "# benign bootstrap")
	s := New(dir, false)
	s.checkStagingPaths([]string{path, path, filepath.Join(dir, "absent")})
	if len(s.Findings) != 1 || s.Findings[0].Severity != SevWarn {
		t.Fatalf("bad staging classification: %+v", s.Findings)
	}
}

func TestUnscannedApplicationContentIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.js")
	writeSparseFixture(t, path, SignatureScanMaxBytes)
	s := New(dir, false)
	s.checkApplicationFile(path)
	if len(findingsFor(s, "scan-incomplete")) != 1 {
		t.Fatal("truncated inspection reported clean")
	}
}

func TestApplicationAppendedPayloadBeyondProjectCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.js")
	writeFixture(t, path, strings.Repeat(" ", 20<<20)+"/*RS260605*/")
	s := New(dir, false)
	s.checkApplicationFile(path)
	if len(findingsFor(s, "patched-application")) != 1 || len(findingsFor(s, "scan-incomplete")) != 0 {
		t.Fatalf("tail not covered: %+v", s.Findings)
	}
}

func TestRecursivePersistenceDiscovery(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		"renamed.app/Contents/Resources/app/out/main.js",
		"portable/resources/app/main.js",
		"nested/node_modules/@vscode/deviceid/dist/index.js",
		"discord/custom/modules/discord_desktop_core/index.js",
		"custom-node/node_modules/npm/lib/cli.js",
	}
	for _, path := range paths {
		writeFixture(t, filepath.Join(root, path), "/*RS260605*/")
	}
	writeFixture(t, filepath.Join(root, "node_modules", "nested", "orphan.inz.orig"), "backup")
	writeFixture(t, filepath.Join(root, "elsewhere", "orphan.inz.cjs"), "fixture")
	writeFixture(t, filepath.Join(root, "clean", "resources", "app", "main.js"), "console.log('hello')")
	s := New(root, false)
	s.walkPersistenceRoot(root)
	s.walkPersistenceRoot(filepath.Join(root, "nested"))
	s.scanProjectDirs()
	if got := len(findingsFor(s, "patched-application")); got != len(paths) {
		t.Fatalf("want %d entrypoints, got %d: %+v", len(paths), got, s.Findings)
	}
	if got := len(findingsFor(s, "malicious-repo-artifact")); got != 2 {
		t.Fatalf("want two sidecars, got %d", got)
	}
	if len(findingsFor(s, "scan-incomplete")) != 0 {
		t.Fatalf("unexpected warning: %+v", s.Findings)
	}
}

func TestPersistenceExplicitMissingRoot(t *testing.T) {
	s := New(t.TempDir(), false)
	s.walkPersistenceRoot(filepath.Join(s.HomeDir, "missing"))
	if len(findingsFor(s, "scan-incomplete")) != 1 {
		t.Fatal("missing explicit root reported clean")
	}
}

func TestPersistenceRootSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	writeFixture(t, filepath.Join(target, "orphan.inz.cjs"), "fixture")
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	s := New(root, false)
	s.walkPersistenceRoot(link)
	s.walkPersistenceRoot(target)
	if len(findingsFor(s, "malicious-repo-artifact")) != 1 {
		t.Fatalf("root symlink missed or duplicated: %+v", s.Findings)
	}
}

func TestGeneralReadFailuresAndTruncationReported(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.config.js")
	writeSparseFixture(t, path, SignatureScanMaxBytes+1)
	s := New(root, false)
	s.checkSourceFile(path, filepath.Base(path))
	s.readCapped(filepath.Join(root, "missing.config.js"))
	if len(findingsFor(s, "scan-incomplete")) != 2 {
		t.Fatalf("incomplete reads reported clean: %+v", s.Findings)
	}
	if s.stats.FilesUnreadable != 2 {
		t.Fatalf("unreadable count: %d", s.stats.FilesUnreadable)
	}
}

func TestGeneralWalkFailureReported(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "missing"), false)
	s.scanProjectDirs()
	if len(findingsFor(s, "scan-incomplete")) != 1 {
		t.Fatal("failed walk reported clean")
	}
}

func TestProjectWalkPreservesPersistenceInsideSkippedTrees(t *testing.T) {
	root := t.TempDir()
	for _, tree := range []string{"node_modules", ".vscode", "vendor"} {
		writeFixture(t, filepath.Join(root, tree, "nested", "orphan.inz.cjs"), "fixture")
		writeFixture(t, filepath.Join(root, tree, "portable", "resources", "app", "main.js"), "/*RS260605*/")
	}
	writeFixture(t, filepath.Join(root, "vendor", "composer", "installed.json"), "[]")
	for _, deep := range []bool{false, true} {
		s := New(root, false)
		s.Deep = deep
		s.scanProjectDirs()
		if len(findingsFor(s, "malicious-repo-artifact")) != 3 || len(findingsFor(s, "patched-application")) != 3 {
			t.Fatalf("deep=%v lost coverage: %+v", deep, s.Findings)
		}
	}
}

func writeSparseFixture(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func TestWholeFileFindsMiddleAndTailBeyondOldLimit(t *testing.T) {
	for _, application := range []bool{false, true} {
		for _, offset := range []int{6 << 20, 20 << 20} {
			dir := t.TempDir()
			path := filepath.Join(dir, "index.js")
			data := []byte(strings.Repeat("x", 21<<20))
			copy(data[offset:], "/*RS260605*/")
			if err := os.WriteFile(path, data, 0644); err != nil {
				t.Fatal(err)
			}
			s := New(dir, false)
			check := "payload-signature"
			if application {
				s.checkApplicationFile(path)
				check = "patched-application"
			} else {
				s.checkSourceFile(path, "index.js")
			}
			if len(findingsFor(s, check)) != 1 || len(findingsFor(s, "scan-incomplete")) != 0 {
				t.Fatalf("whole-file coverage failed: %+v", s.Findings)
			}
		}
	}
}
