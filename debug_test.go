package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugContentAccounting(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "example.js")
	data := []byte("console.log('inert test');\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := New(root, false)
	s.debug = newScanDebug(&out)
	s.debug.stage("projects")
	s.checkSourceFile(path, "example.js")
	s.debug.summary()
	for _, want := range []string{"stage-start=\"projects\"", "open path=", "read path=", "inspect path=", "done path=", fmt.Sprintf("bytes=%d", len(data)), "read=", "inspect=", "top directories by time", "top directories by bytes", "files=1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	if n := s.contentIO.bytes.Load(); n != int64(len(data)) {
		t.Fatalf("bytes = %d, want %d", n, len(data))
	}
}
func TestDebugFlagIndependent(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	m := registerScanModes(fs)
	if err := fs.Parse([]string{"-debug"}); err != nil {
		t.Fatal(err)
	}
	if !m.Debug || !m.Deep || !m.Git || !m.Coverage || m.NpmCache {
		t.Fatalf("unexpected modes: %+v", m)
	}
}

func TestDebugSavedAccounting(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "@scope", "pkg")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "index.js")
	data := []byte("console.log('fixture')")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := New(root, false)
	s.debug = newScanDebug(io.Discard)
	s.debug.stage("projects")
	s.checkSourceFile(path, "index.js")
	if _, err := s.readDir(dir); err != nil {
		t.Fatal(err)
	}
	r := s.debug.snapshot()
	if r.Files[path].Bytes != int64(len(data)) || r.Packages["@scope/pkg"] != int64(len(data)) || r.Directories[dir] != int64(len(data)) {
		t.Fatalf("bad accounting: %+v", r)
	}
	if r.Traversal.Calls != 1 || r.Traversal.Entries != 1 || !strings.Contains(r.Files[path].Selection, "checkSourceFile") {
		t.Fatalf("missing evidence: %+v", r)
	}
	report, err := saveScanReport(root, nil, ScanStats{Debug: r}, "fixture -debug")
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Stats ScanStats `json:"stats"`
	}
	if err := json.Unmarshal(saved, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Stats.Debug.Files[path].Bytes != int64(len(data)) {
		t.Fatal("debug evidence not saved")
	}
}

func TestDebugGitOutputAccounting(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	d := newScanDebug(io.Discard)
	ctx := context.WithValue(context.Background(), debugContextKey{}, d)
	if _, err := gitSmallOutput(ctx, t.TempDir(), "--version"); err != nil {
		t.Fatal(err)
	}
	r := d.snapshot()
	if len(r.GitCommands) != 1 || r.GitCommands[0].StdoutBytes == 0 || r.GitCommands[0].Elapsed <= 0 {
		t.Fatalf("missing Git measurements: %+v", r.GitCommands)
	}
}

func TestQuietDebugKeepsLog(t *testing.T) {
	for _, quiet := range []bool{true, false} {
		var terminal bytes.Buffer
		d, f, err := openDebugLog(t.TempDir(), quiet, &terminal)
		if err != nil {
			t.Fatal(err)
		}
		s := New(t.TempDir(), !quiet)
		s.debug = d
		s.progress("stage progress\n")
		s.log("selected fixture")
		d.event("read", "fixture", 12, 0)
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"stage progress", "selected fixture", "bytes=12"} {
			if !bytes.Contains(data, []byte(want)) {
				t.Fatalf("missing %q from saved debug log", want)
			}
		}
		if quiet && terminal.Len() != 0 {
			t.Fatalf("quiet debug leaked terminal output: %s", terminal.String())
		}
		if !quiet && terminal.String() != string(data) {
			t.Fatal("terminal and log differ")
		}
		info, _ := os.Stat(f.Name())
		if info.Mode().Perm() != 0600 {
			t.Fatal("debug log must be private")
		}
	}
}
