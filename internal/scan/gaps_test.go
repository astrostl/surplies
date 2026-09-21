package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNetworkEndpoints(t *testing.T) {
	for _, tc := range []struct {
		line, ip string
		match    bool
	}{
		{"tcp4 0 0 10.0.0.1.5000 166.88.134.62.443 ESTABLISHED", "166.88.134.62", true},
		{"tcp 0 0 10.0.0.1:5000 166.88.134.62:443 ESTABLISHED", "166.88.134.62", true},
		{"TCP 10.0.0.1:5000 166.88.134.62:443 ESTABLISHED", "166.88.134.62", true},
		{"tcp6 0 0 ::1:5000 ::ffff:166.88.134.62:443 ESTABLISHED", "166.88.134.62", true},
		{"tcp6 0 0 ::1.5000 ::ffff:166.88.134.62.443 ESTABLISHED", "166.88.134.62", true},
		{"tcp6 0 0 ::1.5000 fe80::1%en0.443 ESTABLISHED", "fe80::1", true},
		{"TCP [::1]:5000 [::ffff:166.88.134.62]:443 ESTABLISHED", "166.88.134.62", true},
		{"tcp4 0 0 166.88.134.62.443 10.0.0.1.5000 ESTABLISHED", "166.88.134.62", false},
		{"tcp4 0 0 10.0.0.1.5000 166.88.134.62.443 TIME_WAIT", "166.88.134.62", false},
		{"tcp4 0 0 166.88.134.62.443 *.* LISTEN", "166.88.134.62", false},
		{"tcp 0 0 10.0.0.1:5000 166.88.134.62:443 ESTABLISHED", "166.88.134.6", false},
	} {
		got, err := remoteEndpoints(tc.line)
		if err != nil || got[tc.ip] != tc.match {
			t.Errorf("%s: %v %v", tc.line, got, err)
		}
	}
	if _, err := remoteEndpoints("tcp malformed"); err == nil {
		t.Fatal("malformed collector output accepted")
	}
	// What macOS prints without -l: the address column is cut, so the peer is
	// neither host nor port. It must still read as a gap, because the fix is
	// passing -l, not learning to accept half an address.
	if _, err := remoteEndpoints("tcp6 0 0 fe80::182b:e436:.61643 fe80::1caa:a604:.55584 ESTABLISHED"); err == nil {
		t.Fatal("truncated peer address accepted")
	}
	if runtime.GOOS == "darwin" && !slices.Contains(netstatArgs(), "-l") {
		t.Fatal("macOS collector must ask for full IPv6 addresses")
	}
}
func TestNetworkFailuresAndDNS(t *testing.T) {
	for _, kind := range []string{"empty", "failed", "timeout", "nxdomain", "filtered", "resolver-failed"} {
		t.Run(kind, func(t *testing.T) {
			s := New(t.TempDir(), false)
			collect := func(ctx context.Context) ([]byte, error) {
				switch kind {
				case "failed":
					return nil, errors.New("collector unavailable")
				case "timeout":
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, nil
			}
			lookup := func(ctx context.Context, _ string) ([]string, error) {
				switch kind {
				case "nxdomain":
					return nil, &net.DNSError{IsNotFound: true}
				case "filtered":
					return []string{"127.0.0.1", "::", "10.0.0.1"}, nil
				case "resolver-failed":
					return nil, errors.New("resolver unavailable")
				}
				return []string{"203.0.113.1"}, nil
			}
			s.inspectNetwork(collect, lookup, 30*time.Millisecond)
			failure := kind == "failed" || kind == "timeout" || kind == "resolver-failed"
			if hasIncomplete(s.Findings) != failure {
				t.Fatalf("wrong completeness: %v", s.Findings)
			}
			if len(findingsFor(s, "network-ioc-active-connection")) != 0 {
				t.Fatal("failure created IOC")
			}
			if (kind == "nxdomain" || kind == "filtered") && len(findingsFor(s, "scan-limited")) != len(KnownC2Domains) {
				t.Fatal("missing DNS scope")
			}
		})
	}
}
func TestCheckDrivenSourceScope(t *testing.T) {
	for _, deep := range []bool{false, true} {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"App.js", "tailwind.config.cjs", "component.tsx", "start.py", "script", "node_modules/pkg/source.js"} {
			writeFixture(t, filepath.Join(dir, name), `global['_V']='inert'`)
		}
		writeFixture(t, filepath.Join(dir, "node_modules/pkg/package.json"), `{"main":"source.js"}`)
		s := New(dir, false)
		s.Deep = deep
		s.scanProjectDirs()
		want := 2
		if deep {
			want++
		}
		if len(findingsFor(s, "payload-signature")) != want {
			t.Fatalf("deep=%v: %v", deep, s.Findings)
		}
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"docs/iocs.md", "fixtures/sample.js"} {
		writeFixture(t, filepath.Join(dir, name), `global['_V']='inert'`)
	}
	writeFixture(t, filepath.Join(dir, "binary.js"), "\x00global['_V']='inert'")
	s := New(dir, false)
	s.scanProjectDirs()
	for _, f := range s.Findings {
		if f.Severity == SevCritical {
			t.Fatalf("research/binary misclassified: %v", f)
		}
	}
}
func TestLoaderAndUnicodeHeuristics(t *testing.T) {
	for _, tc := range []struct{ name, text, check string }{
		{"spacing", `global [ "_V" ] = 'inert'`, "loader-variant"},
		{"alias", `renamed(import.meta.url)( './other.cjs')`, "loader-structure"},
		{"escaped", `global['\u005f\u0056']='inert'`, "payload-signature"},
		{"decode", `eval ( Buffer.from ('inert','base64'))`, "suspicious-source-execution"},
		{"unicode", `const x='` + strings.Repeat("\U000e0100", 16) + `'`, "unicode-concealment"},
		{"long", strings.Repeat("a", 3000) + "\u202e", "unicode-concealment"},
		{"joiner", "const fetch\u200cData=1", "unicode-concealment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(t.TempDir(), false)
			s.inspectGeneralContent("source.js", []byte(tc.text))
			if len(findingsFor(s, tc.check)) == 0 {
				t.Fatalf("miss: %v", s.Findings)
			}
		})
	}
	for _, clean := range []string{`createRequire(import.meta.url); require('./legitimate.cjs')`, `/*M123456A*/`, "const a='❤\ufe0f 👩\u200d💻'", "const a='\u202bשלום\u202c'", "const a='فارسی\u200cمتن'", "const a='\ue000'"} {
		s := New(t.TempDir(), false)
		s.inspectGeneralContent("source.js", []byte(clean))
		if len(s.Findings) != 0 {
			t.Errorf("benign flagged %q: %v", clean, s.Findings)
		}
	}
}
func TestPackageCoverageAndHooks(t *testing.T) {
	for _, name := range []string{"repo", "node_modules/pkg"} {
		dir := t.TempDir()
		root := filepath.Join(dir, name)
		writeFixture(t, filepath.Join(root, "package.json"), `{"name":"pkg","scripts":{"prepublish":"node 'setup file.cjs'"}}`)
		writeFixture(t, filepath.Join(root, "setup file.cjs"), `eval(atob('inert'))`)
		s := New(dir, false)
		s.scanProjectDirs()
		if len(findingsFor(s, "obfuscated-install-script")) != 1 {
			t.Fatalf("miss %s: %v", name, s.Findings)
		}
	}
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "package.json"), "{")
	s := New(dir, false)
	s.scanProjectDirs()
	if !hasIncomplete(s.Findings) || s.stats.PackagesScanned != 0 || s.stats.FilesChecked != 0 {
		t.Fatalf("invalid manifest counted complete: %+v %+v", s.Findings, s.stats)
	}
	s = New(dir, false)
	s.checkComposerVendor(dir)
	if !hasIncomplete(s.Findings) {
		t.Fatal("missing selected Composer manifest silent")
	}
	s = New(dir, false)
	s.checkPthFile(dir, "missing.pth")
	if !hasIncomplete(s.Findings) {
		t.Fatal("missing selected pth silent")
	}
}
func TestWorkspaceAndAssetTasks(t *testing.T) {
	for _, tc := range []struct {
		data string
		want bool
	}{
		{`{"tasks":[{"command":"python3","args":["payload.png"]}]}`, true},
		{`{"tasks":[{"command":"npm","args":["run","build"],"runOptions":{"runOn":"folderOpen"}}]}`, false},
		{`{"tasks":[{"command":"echo","args":["node payload.png"]}]}`, false},
		{`{"tasks":[{"command":"echo","osx":{"command":"bun","args":["run","payload.png"]}}]}`, true},
	} {
		s := New(t.TempDir(), false)
		s.checkFontTask("tasks.json", []byte(tc.data))
		if (len(findingsFor(s, "disguised-file-execution-task")) > 0) != tc.want {
			t.Errorf("%s: %v", tc.data, s.Findings)
		}
	}
	for _, value := range []string{`"on"`, `"off"`, `true`, `null`} {
		s := New(t.TempDir(), false)
		s.checkWorkspaceSettings("settings.json", []byte(`{"task.allowAutomaticTasks":`+value+`}`))
		for _, f := range s.Findings {
			if f.Severity != SevInfo {
				t.Fatalf("setting alone escalated: %v", f)
			}
		}
	}
	s := New(t.TempDir(), false)
	s.checkWorkspaceSettings("settings.json", []byte(`{/* comment */ "task.allowAutomaticTasks":"on", "terminal.integrated.automationProfile.osx":{"path":"/bin/zsh"},}`))
	if len(s.Findings) != 1 || s.Findings[0].Severity != SevWarn {
		t.Fatalf("combination missed %v", s.Findings)
	}
}
func TestAssetValidationAndPadding(t *testing.T) {
	for ext, magics := range assetMagics {
		for _, magic := range magics {
			s := New(t.TempDir(), false)
			s.checkDisguisedAsset("asset"+ext, ext, magic)
			if len(s.Findings) != 0 {
				t.Errorf("valid %s flagged", ext)
			}
		}
	}
	for _, ext := range []string{".png", ".wasm", ".pdf", ".mp4"} {
		s := New(t.TempDir(), false)
		s.checkDisguisedAsset("asset"+ext, ext, []byte("\x00\x00   const x=1;"))
		if len(s.Findings) != 1 || s.Findings[0].Severity != SevWarn {
			t.Errorf("disguise %s missed", ext)
		}
	}
	s := New(t.TempDir(), false)
	s.checkFakeFont("font.woff2", ".woff2", []byte("\x00\x00 const x=1"))
	if len(findingsFor(s, "fake-font-payload")) != 1 {
		t.Fatal("padded font missed")
	}
}
func TestStartupAndToolchainDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, ".zshrc"), "# node /tmp/get-pip\necho ok\n")
	s := New(dir, false)
	s.inspectStartupPaths([]string{filepath.Join(dir, ".zshrc")}, nil)
	if len(s.Findings) != 0 {
		t.Fatalf("comment flagged %v", s.Findings)
	}
	writeFixture(t, filepath.Join(dir, "Library/LaunchAgents/test.plist"), "bplist00...")
	s = New(dir, false)
	s.scanProjectDirs()
	if len(findingsFor(s, "scan-limited")) != 1 {
		t.Fatal("binary plist omission silent")
	}
	for _, name := range []string{"node_modules/npm/bin/npm-cli.js", "node_modules/yarn/lib/cli.js", "node_modules/corepack/dist/pnpm.js", ".npm/_npx/cache/node_modules/pnpm/bin/pnpm.cjs", ".local/share/claude/versions/1.0"} {
		writeFixture(t, filepath.Join(dir, name), "/*RS260605*/")
	}
	s = New(dir, false)
	s.scanProjectDirs()
	if len(findingsFor(s, "patched-application")) != 5 {
		t.Fatalf("toolchains missed %v", s.Findings)
	}
}
func TestNetworkCoverageJSON(t *testing.T) {
	s := New(t.TempDir(), false)
	s.networkError("netstat", errors.New("missing"))
	data, _ := json.Marshal(s.Findings)
	if !strings.Contains(string(data), "scan-incomplete") || !strings.Contains(coverageSummary(groupCoverage(s.Findings)), "network collection") {
		t.Fatal("network failure hidden")
	}
}
func TestOversizePackage(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(SignatureScanMaxBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()
	s := New(dir, false)
	s.checkPackage(dir, "pkg")
	if !hasIncomplete(s.Findings) || s.stats.PackagesScanned != 0 {
		t.Fatal("oversized package accepted")
	}
}

func TestLateNetworkCollectorCannotPublish(t *testing.T) {
	s := New(t.TempDir(), false)
	released := make(chan struct{})
	returned := make(chan struct{})
	collector := func(context.Context) ([]byte, error) {
		<-released
		defer close(returned)
		return []byte("TCP 10.0.0.1:1 142.11.206.73:443 ESTABLISHED"), nil
	}
	resolver := func(context.Context, string) ([]string, error) { return []string{"203.0.113.1"}, nil }
	s.inspectNetwork(collector, resolver, 20*time.Millisecond)
	before, _ := json.Marshal(s.Findings)
	close(released)
	<-returned
	after, _ := json.Marshal(s.Findings)
	if string(before) != string(after) || !hasIncomplete(s.Findings) {
		t.Fatalf("late network worker changed findings: %s", after)
	}
}
func TestInvalidManifestsAndSelectedDirectoryFailures(t *testing.T) {
	for _, input := range []string{"null", "[]", "{"} {
		dir := t.TempDir()
		writeFixture(t, filepath.Join(dir, "package.json"), input)
		s := New(dir, false)
		s.checkPackage(dir, "pkg")
		if !hasIncomplete(s.Findings) || s.stats.PackagesScanned != 0 {
			t.Errorf("accepted invalid package %q", input)
		}
	}
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "composer", "installed.json"), "null")
	s := New(dir, false)
	s.checkComposerVendor(dir)
	if !hasIncomplete(s.Findings) || s.stats.ComposerPackagesScanned != 0 {
		t.Fatal("accepted invalid Composer")
	}
	s = New(dir, false)
	s.scanNodeModulesPackages(filepath.Join(dir, "missing"))
	if !hasIncomplete(s.Findings) {
		t.Fatal("selected directory failure ignored")
	}
}
func TestStartupPositiveAndHostsBoundaries(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, ".bashrc"), "node /tmp/get-pip.js\n")
	s := New(dir, false)
	s.inspectStartupPaths([]string{filepath.Join(dir, ".bashrc")}, nil)
	if len(findingsFor(s, "startup-content")) != 1 {
		t.Fatalf("startup missed: %v", s.Findings)
	}
	for _, tc := range []struct {
		input string
		want  int
	}{{"166.88.134.62 host", 1}, {"127.0.0.1 blocked # 166.88.134.62", 0}, {"166.88.134.620 host", 0}} {
		s = New(dir, false)
		s.inspectHosts("hosts", []byte(tc.input))
		if len(findingsFor(s, "hosts-c2-entry")) != tc.want {
			t.Fatalf("hosts %q: %v", tc.input, s.Findings)
		}
	}
}

func TestToolchainsInExtraRootAndBenignEntrypoints(t *testing.T) {
	home, extra := t.TempDir(), t.TempDir()
	target := filepath.Join(extra, "node_modules/corepack/dist/pnpm.js")
	writeFixture(t, target, "/*RS260605*/")
	writeFixture(t, filepath.Join(extra, "node_modules/yarn/lib/cli.js"), "const require = createRequire(import.meta.url); require('./cli.cjs')")
	s := New(home, false)
	s.ExtraRoots = []string{extra}
	s.scanProjectDirs()
	if len(findingsFor(s, "patched-application")) != 1 {
		t.Fatalf("extra-root discovery: %v", s.Findings)
	}
}
func TestWeakCommunityIndicatorsDoNotBecomeMalware(t *testing.T) {
	for _, value := range []string{"__inzV", "app-vscode-eval", "/*M123456A*/", "A9-2896-1", "magicmeta", "Sec-V", "https://api.mainnet-beta.solana.com", "process.env['_H']", "global['_t_s']='https://example.invalid'"} {
		s := New(t.TempDir(), false)
		s.inspectGeneralContent("source.js", []byte(value))
		if len(s.Findings) != 0 {
			t.Fatalf("standalone %q flagged: %v", value, s.Findings)
		}
	}
	s := New(t.TempDir(), false)
	s.inspectGeneralContent("source.js", []byte("/*M123456A*/ renamed(import.meta.url)('./x.cjs')"))
	if len(findingsFor(s, "correlated-loader-markers")) != 1 {
		t.Fatal("correlated community marker missed")
	}
}
func TestAssetEmptyTruncatedAndHTML(t *testing.T) {
	for _, data := range [][]byte{nil, {0x89, 0x50}, []byte("unexpected")} {
		s := New(t.TempDir(), false)
		s.checkDisguisedAsset("a.png", ".png", data)
		if len(s.Findings) != 1 || s.Findings[0].Severity != SevWarn {
			t.Fatalf("malformed asset: %v", s.Findings)
		}
	}
	for _, data := range []string{"<!doctype html><html>404</html>", "\x00\x00 <?xml version='1.0'?><error/>"} {
		s := New(t.TempDir(), false)
		s.checkDisguisedAsset("a.png", ".png", []byte(data))
		if len(s.Findings) != 0 {
			t.Fatalf("download error: %v", s.Findings)
		}
	}
}

func TestSymlinkedInstalledPackageKeepsVersionCoverage(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "store", "axios")
	writeFixture(t, filepath.Join(target, "package.json"), `{"name":"axios","version":"1.14.1"}`)
	nm := filepath.Join(dir, "node_modules")
	if err := os.MkdirAll(nm, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(nm, "axios")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := New(dir, false)
	s.checkNodeModulesDir(nm)
	if len(findingsFor(s, "compromised-version")) != 1 {
		t.Fatalf("symlinked known version lost: %v", s.Findings)
	}
}

func TestOptionalManifestAbsenceVersusSelectedFailure(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, false)
	s.checkPackage(dir, "optional")
	if len(s.Findings) != 0 {
		t.Fatalf("optional absence flagged: %v", s.Findings)
	}
	s = New(dir, false)
	s.checkSourceFile(filepath.Join(dir, "package.json"), "package.json")
	if !hasIncomplete(s.Findings) {
		t.Fatal("selected missing manifest was silent")
	}
}

// --- G17/G18: filename-independent hash identification ---

// A sized entry must be identified under any name and any extension, including
// one that is not otherwise eligible for content inspection.
func TestSizedPayloadHashIsFilenameIndependent(t *testing.T) {
	fixture := []byte("inert sized payload fixture")
	original := KnownRepoPayloadHashes
	KnownRepoPayloadHashes = []RepoPayloadHash{{
		Filename: "published-name.js", SHA256: fmt.Sprintf("%x", sha256.Sum256(fixture)),
		Size: int64(len(fixture)), Desc: "inert sized fixture", Attack: "test",
	}}
	t.Cleanup(func() { KnownRepoPayloadHashes = original })

	for _, name := range []string{"published-name.js", "renamed.cjs", "DO-NOT-RUN__dropper.quarantine", "vendor.bin", "noextension"} {
		dir := t.TempDir()
		project := filepath.Join(dir, "project")
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"p"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, name), fixture, 0o644); err != nil {
			t.Fatal(err)
		}
		s := New(dir, false)
		s.scanProjectDirs()
		found := findingsFor(s, "malicious-repo-artifact")
		if len(found) != 1 {
			t.Fatalf("%s: expected one hash finding, got %+v", name, s.Findings)
		}
		if name != "published-name.js" && !strings.Contains(found[0].Detail, "not by filename") {
			t.Fatalf("%s: rename was not disclosed: %s", name, found[0].Detail)
		}
	}
}

// A same-size file that is not the payload must not be reported, and a
// payload-sized name must not be reported on content alone.
func TestSizedPayloadHashRejectsCollisions(t *testing.T) {
	fixture := []byte("inert sized payload fixture")
	original := KnownRepoPayloadHashes
	KnownRepoPayloadHashes = []RepoPayloadHash{{
		Filename: "published-name.js", SHA256: fmt.Sprintf("%x", sha256.Sum256(fixture)),
		Size: int64(len(fixture)), Desc: "inert sized fixture", Attack: "test",
	}}
	t.Cleanup(func() { KnownRepoPayloadHashes = original })

	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	same := []byte(strings.Repeat("z", len(fixture)))
	if err := os.WriteFile(filepath.Join(project, "collision.bin"), same, 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(dir, false)
	s.scanProjectDirs()
	if len(findingsFor(s, "malicious-repo-artifact")) != 0 {
		t.Fatalf("same-size decoy reported: %+v", s.Findings)
	}
}

// A size-less entry (G17: Socket publishes no sizes) stays name-gated on disk
// and must never make every Git blob a hashing candidate.
func TestSizelessPayloadHashIsNameGatedAndNotAGitCandidate(t *testing.T) {
	fixture := []byte("inert sizeless payload fixture")
	original := KnownRepoPayloadHashes
	KnownRepoPayloadHashes = []RepoPayloadHash{{
		Filename: "tailwind.config.js", SHA256: fmt.Sprintf("%x", sha256.Sum256(fixture)),
		Desc: "inert sizeless fixture", Attack: "test",
	}}
	t.Cleanup(func() { KnownRepoPayloadHashes = original })

	if gitHashCandidate(int64(len(fixture))) || gitHashCandidate(0) || gitHashCandidate(1<<20) {
		t.Fatal("size-less entry made Git blobs candidates")
	}
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "tailwind.config.js"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "renamed.js"), fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(dir, false)
	s.scanProjectDirs()
	found := findingsFor(s, "malicious-repo-artifact")
	if len(found) != 1 || !strings.HasSuffix(found[0].Path, "tailwind.config.js") {
		t.Fatalf("size-less name gating wrong: %+v", s.Findings)
	}
}

// The five published PolinRider hashes must be present, size-less, and unique.
func TestSocketPolinRiderPayloadHashesPresent(t *testing.T) {
	want := []string{
		"7d47c430e6e404dc2fa8b4837678d1cbdb4d0aeacec9b405655cab79d54a2ad9",
		"b7ede935d4979146b55f12b9eec7c83b61962b478f5dc9b8db251e539ec2abd3",
		"ccb187dc9de0cc7477c9817ae53365d273e121407c0305f863e2ab67c35d6395",
		"139ea03dcddf4aa810d55740be3cf6c92ce7a9f3cbcbbb35440e25b769a87683",
		"515a53291d25d229e1f9fa72e66407e1cfd7e77c91478400b24d5185af68531a",
	}
	for _, sha := range want {
		i := slices.IndexFunc(KnownRepoPayloadHashes, func(h RepoPayloadHash) bool { return h.SHA256 == sha })
		if i < 0 {
			t.Fatalf("missing published hash %s", sha)
		}
		if h := KnownRepoPayloadHashes[i]; h.Filename != "tailwind.config.js" || h.Size != 0 {
			t.Fatalf("unexpected metadata for %s: %+v", sha, h)
		}
	}
}
