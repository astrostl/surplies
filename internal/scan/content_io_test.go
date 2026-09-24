package scan

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepBinaryCachesUsePrefixesNotWholeFiles(t *testing.T) {
	root := t.TempDir()
	for i := range 4 {
		path := filepath.Join(root, ".cache", fmt.Sprintf("blob-%d", i))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.Truncate(64 << 20); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	s := New(root, false)
	s.Deep = true
	s.Broad = true // Explicit broad mode still rejects binary bodies early.
	s.scanProjectDirs()
	if got := s.contentIO.bytes.Load(); got != 4*SourceSniffBytes {
		t.Fatalf("read %d bytes for 256 MiB binary cache; want %d", got, 4*SourceSniffBytes)
	}
	if s.stats.BinaryPrefixesSkipped != 4 {
		t.Fatalf("missing exclusion count: %+v", s.stats)
	}
	// Each skipped file is named in a scope notice, and nothing else fires.
	if len(s.Findings) != 4 {
		t.Fatalf("binary cache misclassified: %v", s.Findings)
	}
	for _, f := range s.Findings {
		if f.Check != "scan-limited" || f.Detail != binaryExcludedDetail {
			t.Fatalf("binary cache misclassified: %v", s.Findings)
		}
	}
}

func TestTextStillReadFullyAcrossSniffBoundary(t *testing.T) {
	for _, name := range []string{"loader", "server.js"} {
		root := t.TempDir()
		path := filepath.Join(root, name)
		if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
			t.Fatal(err)
		}
		// Split a valid four-byte rune at the prefix boundary. Never misclassify it.
		data := strings.Repeat("x", SourceSniffBytes-1) + "😀" + strings.Repeat("x", 2<<20) + "/*RS260605*/"
		writeFixture(t, path, data)
		s := New(root, false)
		s.checkSourceFile(path, name)
		if len(findingsFor(s, "payload-signature")) != 1 {
			t.Fatalf("tail marker lost: %v", s.Findings)
		}
		if got := s.contentIO.bytes.Load(); got != int64(len(data)) {
			t.Fatalf("read count=%d want=%d", got, len(data))
		}
		if s.stats.BinaryPrefixesSkipped != 0 {
			t.Fatal("valid Unicode classified as binary")
		}
	}
}

func TestPaddedAssetsStillReadPastSniff(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "padded.woff2")
	data := strings.Repeat("\x00", 4*SourceSniffBytes) + "global['_V']='inert'"
	writeFixture(t, path, data)
	s := New(root, false)
	s.checkSourceFile(path, filepath.Base(path))
	if len(findingsFor(s, "payload-signature")) != 1 || len(findingsFor(s, "fake-font-payload")) != 1 {
		t.Fatalf("padded script lost: %v", s.Findings)
	}
	if got := s.contentIO.bytes.Load(); got != int64(len(data)) {
		t.Fatalf("read count=%d want=%d", got, len(data))
	}
}

func TestExactHashesAndTargetedEntrypointsKeepFullBinaryReads(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, 4*SourceSniffBytes)
	copy(data[len(data)-16:], "/*RS260605*/")
	path := filepath.Join(root, "candidate.js")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	old := KnownRepoPayloadHashes
	KnownRepoPayloadHashes = append(append([]RepoPayloadHash(nil), old...), RepoPayloadHash{Filename: "candidate.js", SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Size: int64(len(data)), Desc: "inert test hash", Attack: "test"})
	t.Cleanup(func() { KnownRepoPayloadHashes = old })
	s := New(root, false)
	s.checkSourceFile(path, filepath.Base(path))
	if len(findingsFor(s, "malicious-repo-artifact")) != 1 || s.contentIO.bytes.Load() != int64(len(data)) {
		t.Fatalf("exact hash lost: %v", s.Findings)
	}
	s = New(root, false)
	s.checkApplicationFile(path)
	if len(findingsFor(s, "patched-application")) != 1 || s.contentIO.bytes.Load() != int64(len(data)) {
		t.Fatalf("targeted entrypoint lost: %v", s.Findings)
	}
}

func TestBinaryPrefixClassification(t *testing.T) {
	for _, tc := range []struct {
		data   string
		binary bool
	}{
		{"hello\x00world", true}, {"hello\xffworld", true}, {"hello😀", false}, {"hello\xf0\x9f", false}, {"hello\xf0x", true}, {"", false},
	} {
		if got := binarySourcePrefix([]byte(tc.data)); got != tc.binary {
			t.Errorf("%q: %v", tc.data, got)
		}
	}
}
