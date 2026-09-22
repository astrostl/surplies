package scan

import (
	"os"
	"syscall"
	"testing"
)

func TestRefusedMaterializationIsNotDownloaded(t *testing.T) {
	s := New(t.TempDir(), false)
	s.scanError("/cloud/dir", &os.PathError{Op: "fdopendir", Path: "/cloud/dir", Err: syscall.EDEADLK})
	s.scanError("/broken", &os.PathError{Op: "open", Path: "/broken", Err: syscall.EIO})
	groups := groupCoverage(s.Findings)
	if len(groups["not downloaded"]) != 1 || groups["not downloaded"][0].Path != "/cloud/dir" {
		t.Fatalf("EDEADLK not classified as not downloaded: %+v", groups)
	}
	if len(groups["other errors"]) != 1 || groups["other errors"][0].Path != "/broken" {
		t.Fatalf("unrelated errno reclassified: %+v", groups)
	}
}
