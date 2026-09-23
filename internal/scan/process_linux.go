package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func listProcesses() (processSnapshot, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return processSnapshot{}, err
	}
	var snap processSnapshot
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join("/proc", e.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			if os.IsPermission(err) {
				snap.restricted++
			}
			continue
		}
		// Kernel threads and zombies have an empty command line.
		raw = bytes.TrimRight(raw, "\x00")
		if len(raw) == 0 {
			continue
		}
		args := strings.Split(string(raw), "\x00")
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))
		cwd, _ := os.Readlink(filepath.Join(dir, "cwd"))
		snap.procs = append(snap.procs, processInfo{PID: pid, Exe: exe, Args: args, Cwd: cwd})
	}
	return snap, nil
}
