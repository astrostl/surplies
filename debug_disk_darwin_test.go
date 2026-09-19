//go:build darwin

package main

import (
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"unsafe"
)

func TestDarwinDiskCounters(t *testing.T) {
	if unsafe.Sizeof(darwinRusageV2{}) != 160 {
		t.Fatal("rusage_info_v2 layout changed")
	}
	f, err := os.CreateTemp(t.TempDir(), "disk-counter")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Force only this 1 MiB fixture through storage instead of relying on cache state.
	const fNoCache = 48
	if _, _, err := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), fNoCache, 1); err != 0 {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	start := selfDiskIO()
	if _, err := io.Copy(io.Discard, f); err != nil {
		t.Fatal(err)
	}
	delta := diskIODelta(start, selfDiskIO())
	if !delta.Available || delta.ReadBytes < 1<<20 {
		t.Fatalf("real uncached read not measured: %+v", delta)
	}
	t.Logf("1 MiB fixture: OS reads=%d bytes", delta.ReadBytes)
}

func TestDarwinExitedChildCounters(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sample := childDiskIO(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !sample.Available {
		t.Fatalf("final child counters unavailable: %+v", sample)
	}
	// An already reaped PID must report unavailable rather than an observed zero.
	if again := pidDiskIO(cmd.Process.Pid); again.Available {
		t.Fatal("reaped child still reported available")
	}
}
