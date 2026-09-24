package scan

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRoutineContentScope(t *testing.T) {
	home := t.TempDir()
	marker := "/*RS260605*/"
	excluded := []string{"data/tokenizer.json", "game/audio.xml", "sessions/chat.json", "downloads/opaque", "documents/notes.txt", "loose/module.py", "loose/script.js", "project/data/settings.json", "project/data/hidden"}
	included := []string{"loose/index.js", "loose/tailwind.config.js", ".vscode/tasks.json", ".npm/_npx/env/node_modules/pkg/data.json"}
	for _, p := range append(append([]string{}, excluded...), included...) {
		writeFixture(t, filepath.Join(home, p), marker)
	}
	writeFixture(t, filepath.Join(home, ".npm/_npx/env/node_modules/pkg/package.json"), `{"main":"data.json"}`)
	writeFixture(t, filepath.Join(home, "project", "package.json"), `{"name":"test"}`)
	for _, all := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		s.Broad = all
		s.scanProjectDirs()
		found := map[string]bool{}
		for _, f := range findingsFor(s, "payload-signature") {
			found[f.Path] = true
		}
		for _, p := range included {
			if !found[filepath.Join(home, p)] {
				t.Errorf("all=%v lost coverage for %s", all, p)
			}
		}
		for _, p := range excluded {
			if found[filepath.Join(home, p)] != all {
				t.Errorf("all=%v unexpected scope for %s", all, p)
			}
		}
	}
}
func TestBrowserCachePrunedButExtensionsRetained(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, "Library", "Caches", "Microsoft Edge")
	writeFixture(t, filepath.Join(cache, "Profile 1", "Cache", "node_modules", "pkg", "index.js"), "/*RS260605*/")
	writeFixture(t, filepath.Join(cache, "Profile 1/Cache/node_modules/pkg/package.json"), `{"main":"index.js"}`)
	extension := filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Default", "Extensions", "pkg", "Cache", "index.js")
	writeFixture(t, extension, "/*RS260605*/")
	for _, all := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		s.BrowserCache = all
		visited := false
		s.walkScanRoots(func(path string, d fs.DirEntry, err error) error {
			if path == cache {
				visited = true
			}
			return nil
		})
		s.scanProjectDirs()
		if visited != all {
			t.Fatalf("all=%v visited browser cache=%v", all, visited)
		}
		want := 1
		if all {
			want = 2
		}
		if got := len(findingsFor(s, "payload-signature")); got != want {
			t.Fatalf("got %d want %d: %v", got, want, s.Findings)
		}
	}
}
func TestUnrelatedDataZeroContentReads(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"tokenizer.json", "audio.xml", "opaque", "history.txt", "font.woff2"} {
		writeFixture(t, filepath.Join(home, "data", name), "/*RS260605*/")
	}
	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()
	if n := s.contentIO.bytes.Load(); n != 0 {
		t.Fatalf("unrelated data read %d bytes", n)
	}
}
func TestBroadExplicitAndExtraRoot(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	m := RegisterScanModes(f)
	if err := f.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	if m.Broad {
		t.Fatal("default enabled broad content")
	}
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "tailwind.config.js"), "/*RS260605*/")
	s := New(t.TempDir(), false)
	s.ExtraRoots = []string{root}
	s.scanProjectDirs()
	if len(findingsFor(s, "payload-signature")) != 1 {
		t.Fatal("explicit root did not find injection candidate")
	}
}

// Small inert corpus: browser objects and model data alongside source code.
// Run with -benchtime=1x for bounded before/after scope measurements.
func BenchmarkContentScope(b *testing.B) {
	home := b.TempDir()
	blob := bytes.Repeat([]byte("ordinary model data\n"), 2048)
	for _, dir := range []string{"models", "Library/Caches/Microsoft Edge/Profile 1/Cache"} {
		full := filepath.Join(home, dir)
		if err := os.MkdirAll(full, 0700); err != nil {
			b.Fatal(err)
		}
		for i := range 64 {
			if err := os.WriteFile(filepath.Join(full, fmt.Sprintf("%d.json", i)), blob, 0600); err != nil {
				b.Fatal(err)
			}
		}
	}
	code := filepath.Join(home, "index.js")
	if err := os.WriteFile(code, []byte("console.log('fixture');"), 0600); err != nil {
		b.Fatal(err)
	}
	for _, all := range []bool{true, false} {
		b.Run(fmt.Sprintf("all-content=%v", all), func(b *testing.B) {
			var total int64
			for i := 0; i < b.N; i++ {
				s := New(home, false)
				s.Deep = true
				s.Broad = all
				s.scanProjectDirs()
				total += s.contentIO.bytes.Load()
			}
			b.ReportMetric(float64(total)/float64(b.N), "read-bytes/op")
		})
	}
}

func TestHomeManifestDoesNotTurnHomeIntoProject(t *testing.T) {
	home := t.TempDir()
	manifest := `{"name":"home-tools"}`
	writeFixture(t, filepath.Join(home, "package.json"), manifest)
	// Dotfiles repositories must not accidentally broaden the scope either.
	if err := os.Mkdir(filepath.Join(home, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"Documents/curseforge/minecraft/Install/assets/objects/3c/3ce97077a760a299bf919e7d6464e451a852c670", "Library/data/tokenizer.json", "Downloads/data.xml", ".cache/opaque"} {
		writeFixture(t, filepath.Join(home, path), "/*RS260605*/")
	}
	projectManifest := `{"name":"actual-project"}`
	writeFixture(t, filepath.Join(home, "src/project/package.json"), projectManifest)
	writeFixture(t, filepath.Join(home, "src/project/tailwind.config.js"), "/*RS260605*/")
	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()
	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 || hits[0].Path != filepath.Join(home, "src/project/tailwind.config.js") {
		t.Fatalf("scope leaked or project lost: %v", hits)
	}
	want := int64(len(manifest) + len(projectManifest) + len("/*RS260605*/"))
	if got := s.contentIO.bytes.Load(); got != want {
		t.Fatalf("read %d bytes, selected files require %d", got, want)
	}
}

func TestProjectAndExplicitRootNeverSelectAllSource(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "src", "project")
	manifest := `{"name":"fixture"}`
	writeFixture(t, filepath.Join(project, "package.json"), manifest)
	// Every former blanket selection route: source extensions, data extensions,
	// extensionless executable, project membership and explicit extra root.
	for _, name := range []string{"bulk.js", "types.d.ts", "data.py", "data.json", "data.xml", "notes.md", "blob"} {
		path := filepath.Join(project, "assets", name)
		writeFixture(t, path, "/*RS260605*/")
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	candidate := filepath.Join(project, "tailwind.config.js")
	writeFixture(t, candidate, "/*RS260605*/")
	for _, extra := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		if extra {
			s.ExtraRoots = []string{project}
		}
		s.scanProjectDirs()
		hits := findingsFor(s, "payload-signature")
		if len(hits) != 1 || hits[0].Path != candidate {
			t.Fatalf("extra=%v selection leaked: %v", extra, hits)
		}
		want := int64(len(manifest) + len("/*RS260605*/"))
		if n := s.contentIO.bytes.Load(); n != want {
			t.Fatalf("extra=%v read %d want %d", extra, n, want)
		}
	}
}

func TestContentExpansionFlagsIndependent(t *testing.T) {
	home := t.TempDir()
	marker := "/*RS260605*/"
	paths := []string{"documents/notes.txt", "Library/Application Support/Google/Chrome/Default/Cache/nested/object", ".npm/_cacache/content-v2/object"}
	for _, path := range paths {
		writeFixture(t, filepath.Join(home, path), marker)
	}
	for mask := range 8 {
		t.Run(fmt.Sprintf("options-%d", mask), func(t *testing.T) {
			flags := flag.NewFlagSet("test", flag.ContinueOnError)
			modes := RegisterScanModes(flags)
			var args []string
			for bit, name := range []string{"-broad", "-browser-cache", "-npm-cache"} {
				if mask&(1<<bit) != 0 {
					args = append(args, name)
				}
			}
			if err := flags.Parse(args); err != nil {
				t.Fatal(err)
			}
			s := New(home, false)
			s.Deep, s.Broad, s.BrowserCache, s.NpmCache = modes.Deep, modes.Broad, modes.BrowserCache, modes.NpmCache
			s.scanProjectDirs()
			found := map[string]bool{}
			for _, finding := range findingsFor(s, "payload-signature") {
				found[finding.Path] = true
			}
			wantBytes := int64(0)
			for bit, path := range paths {
				want := mask&(1<<bit) != 0
				if found[filepath.Join(home, path)] != want {
					t.Errorf("%v: unexpected selection for %s", args, path)
				}
				if want {
					wantBytes += int64(len(marker))
				}
			}
			if got := s.contentIO.bytes.Load(); got != wantBytes {
				t.Fatalf("read %d bytes, want %d", got, wantBytes)
			}
		})
	}
}

// The August wave appended its payload to the last line of a file the project
// already loaded, so its carriers are ordinary source files rather than
// configs. Two were observed by name; they are read on that basis alone, and
// project membership still selects nothing around them.
func TestAugustCarrierNamesReadWithoutWideningProjectScope(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "src", "project")
	manifest := `{"name":"fixture"}`
	writeFixture(t, filepath.Join(project, "package.json"), manifest)

	// The observed August landing: payload behind a long space run on the
	// file's last line. Signature stands in for the real sample's bytes.
	payload := "module.exports={};" + strings.Repeat(" ", 507) + "/*RS260605*/"
	carriers := []string{
		filepath.Join(project, "api_manager.js"),
		filepath.Join(project, "skills", "helm", "generate.js"),
	}
	for _, path := range carriers {
		writeFixture(t, path, payload)
	}

	// Same bytes, same project, names nobody observed: still not read.
	for _, name := range []string{"helper.js", "util.mjs", "service.ts"} {
		decoy := filepath.Join(project, "lib", name)
		writeFixture(t, decoy, payload)
		if err := os.Chmod(decoy, 0755); err != nil {
			t.Fatal(err)
		}
	}

	for _, extra := range []bool{false, true} {
		s := New(home, false)
		s.Deep = true
		if extra {
			s.ExtraRoots = []string{project}
		}
		s.scanProjectDirs()

		hits := findingsFor(s, "payload-signature")
		if len(hits) != len(carriers) {
			t.Fatalf("extra=%v want %d carrier findings, got %d: %v", extra, len(carriers), len(hits), hits)
		}
		for _, h := range hits {
			if !slices.Contains(carriers, h.Path) {
				t.Fatalf("extra=%v unobserved name read: %s", extra, h.Path)
			}
		}
		want := int64(len(manifest) + len(carriers)*len(payload))
		if n := s.contentIO.bytes.Load(); n != want {
			t.Fatalf("extra=%v read %d bytes want %d", extra, n, want)
		}
	}
}

// generate.js is a generic name. Widening the read set to include it must not
// turn an ordinary one into a finding.
func TestAugustCarrierNamesCleanNotFlagged(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "src", "project")
	writeFixture(t, filepath.Join(project, "package.json"), `{"name":"fixture"}`)
	writeFixture(t, filepath.Join(project, "api_manager.js"),
		"module.exports = { get() { return 1; } };\n")
	writeFixture(t, filepath.Join(project, "skills", "helm", "generate.js"),
		"export function generate(spec) {\n  return render(spec);\n}\n")

	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()

	for _, check := range []string{"payload-signature", "padded-source-file"} {
		if hits := findingsFor(s, check); len(hits) != 0 {
			t.Errorf("clean August carrier produced %s findings: %v", check, hits)
		}
	}
}

// -only exists for one-off checks of a single tree and for fast iteration on
// fixtures. It must not quietly widen back out to the machine: every check
// anchored at a fixed system path, at home, at live connections or at temp
// dirs is skipped, and the walk stays inside the roots it was given.
func TestOnlySkipsMachineWideChecks(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "target")
	writeFixture(t, filepath.Join(target, "package.json"), `{"name":"fixture"}`)
	carrier := filepath.Join(target, "api_manager.js")
	writeFixture(t, carrier, "module.exports={};"+strings.Repeat(" ", 507)+"/*RS260605*/")

	// A sibling of the root, reachable only if the walk escapes upward.
	outside := filepath.Join(home, "outside")
	writeFixture(t, filepath.Join(outside, "package.json"), `{"name":"outside"}`)
	writeFixture(t, filepath.Join(outside, "api_manager.js"), "module.exports={};"+strings.Repeat(" ", 507)+"/*RS260605*/")

	s := New(target, false)
	s.Only = true
	s.Deep = true
	findings, _ := s.Run()

	var paths []string
	for _, f := range findings {
		if f.Check == "payload-signature" {
			paths = append(paths, f.Path)
		}
	}
	if len(paths) != 1 || paths[0] != carrier {
		t.Fatalf("want only %s, got %v", carrier, paths)
	}
	// The skipped phases must contribute nothing, including coverage rows.
	for _, f := range findings {
		if strings.HasPrefix(f.Path, outside) {
			t.Errorf("-only escaped its root: %+v", f)
		}
	}
}

// A lifecycle target is a manifest-supplied relative path, so "../" reaches
// out of the package and, under -only, out of the tree the user named. The
// same manifest must still reach that target when the scan is not confined.
func TestOnlyContainsLifecycleScriptTargets(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "target")
	writeFixture(t, filepath.Join(target, "pkg", "package.json"),
		`{"name":"escape","version":"1.0.0","scripts":{"postinstall":"node ../../outside/evil.js"}}`)
	outside := filepath.Join(home, "outside")
	escaped := filepath.Join(outside, "evil.js")
	writeFixture(t, escaped, "module.exports={};"+strings.Repeat(" ", 507)+"/*RS260605*/")

	s := New(target, false)
	s.Only = true
	s.Deep = true
	findings, _ := s.Run()
	for _, f := range findings {
		if strings.HasPrefix(f.Path, outside) {
			t.Errorf("-only read a lifecycle target outside its root: %+v", f)
		}
	}

	// Unconfined, the escape is still inspected: that is what makes the
	// assertion above the gate's doing rather than an unreadable fixture.
	wide := New(home, false)
	wide.Deep = true
	findings, _ = wide.Run()
	var hit bool
	for _, f := range findings {
		if f.Check == "payload-signature" && f.Path == escaped {
			hit = true
		}
	}
	if !hit {
		t.Errorf("lifecycle target outside the package was not inspected: %+v", findings)
	}
}

// -only makes the first -root take home's place, so a home-anchored artifact
// path resolves inside the requested tree and is in scope. Skipping the whole
// phase used to hide it: pointing -only at an extracted home backup reported
// nothing, however infected the backup was.
func TestOnlyChecksRootRelativeArtifacts(t *testing.T) {
	root := t.TempDir()
	planted := filepath.Join(root, ".config", "sysmon", "sysmon.py")
	writeFixture(t, planted, "# litellm backdoor placeholder\n")

	s := New(root, false)
	s.Only = true
	findings, _ := s.Run()

	var hit bool
	for _, f := range findings {
		if f.Check == "known-artifact" && f.Path == planted {
			hit = true
		}
		if !strings.HasPrefix(f.Path, root) && f.Path != "content" && f.Path != "dependencies" {
			t.Errorf("-only reported a path outside its root: %+v", f)
		}
	}
	if !hit {
		t.Errorf("artifact inside the root was not reported: %+v", findings)
	}
}

// The system Python paths are fixed machine-wide locations, not directories
// the user pointed at, so -only must not read them either. The count is the
// assertion: a system site-packages is usually clean, so the leak produces no
// finding and would otherwise stay invisible.
func TestOnlySkipsSystemPythonPaths(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "package.json"), `{"name":"fixture"}`)

	bare := New(root, false)
	bare.Only = true
	if _, stats := bare.Run(); stats.SitePackagesFound != 0 {
		t.Fatalf("-only inspected %d site-packages outside its root", stats.SitePackagesFound)
	}

	// The phase itself still runs: a site-packages inside the root is checked.
	inside := filepath.Join(root, "venv", "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(filepath.Join(inside, "litellm-1.82.7.dist-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := New(root, false)
	s.Only = true
	findings, stats := s.Run()
	if stats.SitePackagesFound != 1 {
		t.Fatalf("site-packages inside the root: found %d, want 1", stats.SitePackagesFound)
	}
	var hit bool
	for _, f := range findings {
		if f.Check == "compromised-python-version" && strings.HasPrefix(f.Path, inside) {
			hit = true
		}
	}
	if !hit {
		t.Errorf("compromised version inside the root was not reported: %+v", findings)
	}
}

// The same tree without -only reaches the machine-wide checks, which is what
// makes the assertion above a real difference rather than a fixture artifact.
func TestOnlyIsWhatSuppressesThePhases(t *testing.T) {
	home := t.TempDir()
	writeFixture(t, filepath.Join(home, "package.json"), `{"name":"fixture"}`)

	quiet := New(home, false)
	quiet.Only = true
	quietFindings, _ := quiet.Run()

	full := New(home, false)
	fullFindings, _ := full.Run()

	if len(fullFindings) <= len(quietFindings) {
		t.Fatalf("-only produced %d findings, full run %d: expected the full run to check more",
			len(quietFindings), len(fullFindings))
	}
}

// The config-append variant's published hashes describe a span inside a
// carrier, not a file: the carrier is the victim's own build config, so its
// file hash is unique per victim and matches nothing. Detection therefore has
// to carve the appended span out of the padded line and hash that.
func TestPaddedSegmentIsCarvedAndHashed(t *testing.T) {
	payload := "module.exports=0;" + strings.Repeat("z", 400) + ";//end"
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))

	restore := KnownRepoPayloadHashes
	KnownRepoPayloadHashes = append(slices.Clone(restore), RepoPayloadHash{
		SHA256: sum,
		Size:   int64(len(payload)),
		Desc:   "test config-append payload",
		Attack: "test",
	})
	t.Cleanup(func() { KnownRepoPayloadHashes = restore })

	home := t.TempDir()
	project := filepath.Join(home, "proj")
	writeFixture(t, filepath.Join(project, "package.json"), `{"name":"fixture"}`)
	// The real shape: an ordinary config whose LAST line carries the payload
	// behind a long space run. The file's own size and hash are arbitrary.
	carrier := filepath.Join(project, "eslint.config.js")
	writeFixture(t, carrier, "export default [\n  { rules: {} },\n];"+strings.Repeat(" ", 507)+payload)

	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()

	hits := findingsFor(s, "payload-signature")
	if len(hits) != 1 {
		t.Fatalf("carved span not matched: %v", hits)
	}
	if hits[0].Severity != SevCritical {
		t.Errorf("want critical, got %v", hits[0].Severity)
	}
	if !strings.Contains(hits[0].Detail, "span appended to this file") {
		t.Errorf("detail should say it matched a span, not the file: %q", hits[0].Detail)
	}
	// A span hit is specific; the generic padding warning must not also fire.
	if warn := findingsFor(s, "padded-source-file"); len(warn) != 0 {
		t.Errorf("padding warning duplicated a confirmed hash hit: %v", warn)
	}
}

// The same carrier without a matching span stays a warning, so carving cannot
// turn an ordinary padded file into a critical.
func TestPaddedSegmentWithoutMatchStaysWarning(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	writeFixture(t, filepath.Join(project, "package.json"), `{"name":"fixture"}`)
	writeFixture(t, filepath.Join(project, "eslint.config.js"),
		"export default []"+strings.Repeat(" ", 507)+";var somethingElse=1;")

	s := New(home, false)
	s.Deep = true
	s.scanProjectDirs()

	if hits := findingsFor(s, "payload-signature"); len(hits) != 0 {
		t.Errorf("unmatched span produced a critical: %v", hits)
	}
	if hits := findingsFor(s, "padded-source-file"); len(hits) != 1 {
		t.Errorf("want 1 padding warning, got %d", len(hits))
	}
}
