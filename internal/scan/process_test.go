package scan

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func withSelf(procs ...processInfo) processSnapshot {
	return processSnapshot{procs: append(procs, processInfo{PID: os.Getpid(), Args: os.Args})}
}

func TestRunningPayloadProcess(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("public/fonts/fa-solid-400.woff2", "setTimeout(() => {}, 1000)\n")
	signed := write("loader.js", "global['!']='x';\n")
	write("server.js", "require('http').createServer().listen(3000)\n")

	cases := []struct {
		name string
		proc processInfo
		want string
	}{
		{"node runs a font", processInfo{PID: 101, Args: []string{"node", "public/fonts/fa-solid-400.woff2"}, Cwd: dir}, filepath.Join(dir, "public/fonts/fa-solid-400.woff2")},
		{"node options before a font", processInfo{PID: 102, Args: []string{`C:\Program Files\nodejs\node.exe`, "--max-old-space-size=4096", "-r", "dotenv/config", "public/fonts/fa-solid-400.woff2"}, Cwd: dir}, filepath.Join(dir, "public/fonts/fa-solid-400.woff2")},
		{"script carries a signature", processInfo{PID: 103, Exe: "/usr/local/bin/node", Args: []string{"node", signed}}, signed},
		{"sidecar on any command line", processInfo{PID: 104, Args: []string{"/Applications/Foo.app/Contents/MacOS/Foo", "--require=/Applications/Foo.app/Contents/Resources/app/main.inz.cjs"}}, "/Applications/Foo.app/Contents/Resources/app/main.inz.cjs"},
		{"clean node server", processInfo{PID: 105, Args: []string{"node", "server.js"}, Cwd: dir}, ""},
		{"inline program", processInfo{PID: 106, Args: []string{"node", "-e", "setTimeout(()=>{},1)"}, Cwd: dir}, ""},
		{"font copied, not executed", processInfo{PID: 107, Args: []string{"cp", "public/fonts/fa-solid-400.woff2", "/tmp/x"}, Cwd: dir}, ""},
		{"search for sidecars", processInfo{PID: 108, Args: []string{"find", ".", "-name", "*.inz.cjs"}}, ""},
		{"grep for sidecars", processInfo{PID: 109, Args: []string{"grep", "-r", `\.inz\.cjs`, "."}}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New(t.TempDir(), false)
			s.inspectProcesses(func() (processSnapshot, error) { return withSelf(c.proc), nil })
			got := findingsFor(s, "running-payload-process")
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("unexpected finding: %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Path != c.want || got[0].Severity != SevCritical {
				t.Fatalf("want one critical finding at %s, got %+v", c.want, got)
			}
			if hasIncomplete(s.Findings) {
				t.Fatalf("clean collection reported incomplete: %+v", s.Findings)
			}
		})
	}
}

func TestRunningProcessScopeAndFailures(t *testing.T) {
	s := New(t.TempDir(), false)
	s.inspectProcesses(func() (processSnapshot, error) {
		snap := withSelf(processInfo{PID: 200, Args: []string{"node", "relative.js"}})
		snap.restricted = 7
		return snap, nil
	})
	limited := findingsFor(s, "scan-limited")
	if len(limited) != 2 || hasIncomplete(s.Findings) {
		t.Fatalf("want two scope notices and complete coverage, got %+v", s.Findings)
	}

	s = New(t.TempDir(), false)
	s.inspectProcesses(func() (processSnapshot, error) { return processSnapshot{}, errors.New("denied") })
	if !hasIncomplete(s.Findings) {
		t.Fatal("collector failure must report incomplete coverage")
	}

	s = New(t.TempDir(), false)
	s.inspectProcesses(func() (processSnapshot, error) {
		return processSnapshot{procs: []processInfo{{PID: 1, Args: []string{"init"}}}}, nil
	})
	if !hasIncomplete(s.Findings) {
		t.Fatal("a snapshot missing this process must report incomplete coverage")
	}
}

// Under -only a process counts only when the file it runs is inside a root.
func TestRunningProcessOnlyScope(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	for _, dir := range []string{root, outside} {
		if err := os.WriteFile(filepath.Join(dir, "fa-solid-400.woff2"), []byte("setTimeout(()=>{},1)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "loader.js"), []byte("global['!']='x';\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := New(root, false)
	s.Only = true
	s.inspectProcesses(func() (processSnapshot, error) {
		return withSelf(
			processInfo{PID: 301, Args: []string{"node", "fa-solid-400.woff2"}, Cwd: root},
			processInfo{PID: 302, Args: []string{"node", filepath.Join(outside, "fa-solid-400.woff2")}},
			processInfo{PID: 303, Args: []string{"node", filepath.Join(outside, "loader.js")}},
			processInfo{PID: 304, Args: []string{"electron", "--require=" + filepath.Join(outside, "main.inz.cjs")}},
			processInfo{PID: 305, Args: []string{"node", "fa-solid-400.woff2"}},
		), nil
	})
	got := findingsFor(s, "running-payload-process")
	if len(got) != 1 || got[0].Path != filepath.Join(root, "fa-solid-400.woff2") {
		t.Fatalf("want only the in-root process, got %+v", got)
	}
	if len(findingsFor(s, "scan-limited")) != 1 {
		t.Fatalf("want one notice for the unresolvable relative script, got %+v", s.Findings)
	}
}

// The real collector must see this test binary with its exact arguments.
func TestListProcessesSeesSelf(t *testing.T) {
	snap, err := listProcesses()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(snap.procs, func(p processInfo) bool { return p.PID == os.Getpid() })
	if i < 0 {
		t.Fatalf("own PID missing from %d processes", len(snap.procs))
	}
	self := snap.procs[i]
	if !slices.Equal(self.Args, os.Args) {
		t.Fatalf("args %q, want %q", self.Args, os.Args)
	}
	// launchd is root's, so an unprivileged macOS run always has one.
	if runtime.GOOS == "darwin" && os.Getuid() != 0 && snap.restricted == 0 {
		t.Fatal("other users' processes were not counted as unreadable")
	}
	if runtime.GOOS != "windows" {
		wd, _ := os.Getwd()
		want, _ := filepath.EvalSymlinks(wd)
		if self.Cwd != want {
			t.Fatalf("cwd %q, want %q", self.Cwd, want)
		}
	}
}

// End to end through the kernel's view of a real Node process, not an
// injected snapshot.
func TestLiveNodeProcesses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	font := filepath.Join(dir, "public", "fonts", "fa-solid-400.woff2")
	if err := os.MkdirAll(filepath.Dir(font), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(font, []byte("setTimeout(() => {}, 60000)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(dir, "index.inz.cjs")
	fontArg := filepath.Join("public", "fonts", "fa-solid-400.woff2")
	if runtime.GOOS == "windows" {
		fontArg = font // no working directory to resolve against
	}
	start := func(args ...string) *exec.Cmd {
		cmd := exec.Command(node, args...)
		cmd.Dir = dir
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	fontProc := start(fontArg)
	sidecarProc := start("-e", "setTimeout(() => {}, 60000)", sidecar)

	deadline := time.Now().Add(10 * time.Second)
	for {
		s := New(t.TempDir(), false)
		s.checkProcesses()
		got := map[string]Finding{}
		for _, f := range findingsFor(s, "running-payload-process") {
			got[f.Path] = f
		}
		fontHit, fontOK := got[font]
		sideHit, sideOK := got[sidecar]
		if fontOK && sideOK {
			if !strings.Contains(fontHit.Detail, "PID "+strconv.Itoa(fontProc.Process.Pid)) || !strings.Contains(sideHit.Detail, "PID "+strconv.Itoa(sidecarProc.Process.Pid)) {
				t.Fatalf("findings name the wrong processes: %+v %+v", fontHit, sideHit)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("live node processes not reported: %+v", s.Findings)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
