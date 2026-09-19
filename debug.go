package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Debug output stays on stderr, separate from JSON findings. It contains paths
// and measurements, never file contents. Workers share this synchronized sink.
type scanDebug struct {
	mu          sync.Mutex
	out         io.Writer
	started     time.Time
	phase       string
	phaseStart  time.Time
	dirs        map[string]debugTotals
	report      DebugReport
	reasons     map[string]string
	phaseDiskIO DebugDiskIO
}
type debugTotals struct {
	files                  int
	bytes                  int64
	read, inspect, elapsed time.Duration
}

func newScanDebug(out io.Writer) *scanDebug {
	return &scanDebug{out: out, started: time.Now(), dirs: make(map[string]debugTotals), reasons: make(map[string]string), report: DebugReport{Files: make(map[string]DebugFile), Stages: make(map[string]time.Duration), DiskIOStart: selfDiskIO(), StageDiskIO: make(map[string]DebugDiskIO)}}
}
func (d *scanDebug) event(action, path string, bytes int64, elapsed time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if strings.HasPrefix(action, "selected-") {
		d.reasons[path] = action
	}
	fmt.Fprintf(d.out, "[debug] +%s %s path=%q bytes=%d elapsed=%s\n", time.Since(d.started).Round(time.Millisecond), action, path, bytes, elapsed.Round(time.Microsecond))
}
func (d *scanDebug) stage(name string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stageLocked(name)
}
func (d *scanDebug) stageLocked(name string) {
	sample := selfDiskIO()
	if d.phase != "" {
		d.report.Stages[d.phase] += time.Since(d.phaseStart)
		d.report.StageDiskIO[d.phase] = diskIODelta(d.phaseDiskIO, sample)
		fmt.Fprintf(d.out, "[debug] stage=%q scanner-disk-io=%+v\n", d.phase, d.report.StageDiskIO[d.phase])
		fmt.Fprintf(d.out, "[debug] stage=%q elapsed=%s\n", d.phase, time.Since(d.phaseStart).Round(time.Millisecond))
	}
	d.phase, d.phaseStart = name, time.Now()
	d.phaseDiskIO = sample
	if name != "" {
		fmt.Fprintf(d.out, "[debug] stage-start=%q\n", name)
	}
}
func (d *scanDebug) fileDone(path string, stats *contentReadStats, read, inspect, elapsed time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := stats.bytes.Load()
	fmt.Fprintf(d.out, "[debug] done path=%q bytes=%d read=%s inspect=%s total=%s\n", path, n, read.Round(time.Microsecond), inspect.Round(time.Microsecond), elapsed.Round(time.Microsecond))
	f := d.report.Files[path]
	f.Reads++
	f.Bytes += n
	f.ReadTime += read
	f.InspectTime += inspect
	f.Stage = d.phase
	f.Selection = d.reasons[path]
	if f.Selection == "" {
		f.Selection = "targeted content check (specific rule not recorded)"
	}
	f.Package = debugPackage(path)
	d.report.Files[path] = f
	dir := filepath.Dir(path)
	t := d.dirs[dir]
	t.files++
	t.bytes += n
	t.read += read
	t.inspect += inspect
	t.elapsed += elapsed
	d.dirs[dir] = t
}
func (d *scanDebug) summary() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stageLocked("")
	dirs := make([]string, 0, len(d.dirs))
	for dir := range d.dirs {
		dirs = append(dirs, dir)
	}
	// Show both rankings: slow small files and fast large reads are different problems.
	for _, metric := range []string{"time", "bytes"} {
		sort.Slice(dirs, func(i, j int) bool {
			a, b := d.dirs[dirs[i]], d.dirs[dirs[j]]
			if metric == "time" && a.elapsed != b.elapsed {
				return a.elapsed > b.elapsed
			}
			if metric == "bytes" && a.bytes != b.bytes {
				return a.bytes > b.bytes
			}
			return dirs[i] < dirs[j]
		})
		fmt.Fprintf(d.out, "[debug] top directories by %s (direct files; nested inspection times may overlap):\n", metric)
		for i, dir := range dirs {
			if i == 20 {
				break
			}
			t := d.dirs[dir]
			fmt.Fprintf(d.out, "[debug] directory=%q files=%d bytes=%d read=%s inspect=%s total=%s\n", dir, t.files, t.bytes, t.read.Round(time.Millisecond), t.inspect.Round(time.Millisecond), t.elapsed.Round(time.Millisecond))
		}
	}
}

// Durations are nanoseconds. Byte counts are logical reads, not physical disk traffic.
type DebugFile struct {
	Bytes                     int64
	Reads                     int
	ReadTime, InspectTime     time.Duration
	Stage, Selection, Package string
}
type DebugTraversal struct {
	Calls, Entries, Errors int64
	Elapsed                time.Duration
}
type DebugGitCommand struct {
	DiskIO                   DebugDiskIO
	Repository               string
	Args                     []string
	StdoutBytes, StderrBytes int64
	Elapsed                  time.Duration
	Error                    string
}
type DebugReport struct {
	Files                                              map[string]DebugFile
	Directories                                        map[string]int64
	Packages                                           map[string]int64
	Stages                                             map[string]time.Duration
	Traversal                                          DebugTraversal
	GitCommands                                        []DebugGitCommand
	DiskIOStart, DiskIOEnd                             DebugDiskIO
	ScannerDiskIO                                      DebugDiskIO
	StageDiskIO                                        map[string]DebugDiskIO
	GitDiskReadBytes, GitDiskWriteBytes                uint64
	GitDiskCommandsMeasured, GitDiskCommandsUnmeasured int
	DebugLog                                           string
	Accounting                                         string
}

func debugPackage(path string) string {
	p := filepath.ToSlash(path)
	if i := strings.LastIndex(p, "/node_modules/"); i >= 0 {
		parts := strings.Split(p[i+14:], "/")
		if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
			return parts[0] + "/" + parts[1]
		}
		return parts[0]
	}
	if i := strings.LastIndex(p, "/site-packages/"); i >= 0 {
		return "python:" + strings.Split(p[i+15:], "/")[0]
	}
	return "(non-package)"
}
func (d *scanDebug) snapshot() *DebugReport {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stageLocked("")
	r := d.report
	r.Files = make(map[string]DebugFile, len(d.report.Files))
	r.Directories = make(map[string]int64)
	r.Packages = make(map[string]int64)
	for p, f := range d.report.Files {
		r.Files[p] = f
		r.Directories[filepath.Dir(p)] += f.Bytes
		r.Packages[f.Package] += f.Bytes
	}
	r.DiskIOEnd = selfDiskIO()
	r.ScannerDiskIO = diskIODelta(r.DiskIOStart, r.DiskIOEnd)
	for _, c := range r.GitCommands {
		if c.DiskIO.Available {
			r.GitDiskCommandsMeasured++
			r.GitDiskReadBytes += c.DiskIO.ReadBytes
			r.GitDiskWriteBytes += c.DiskIO.WriteBytes
		} else {
			r.GitDiskCommandsUnmeasured++
		}
	}
	r.Accounting = "Content bytes count application reads. Directory enumeration counts/timing do not measure metadata bytes. Git stdout/stderr bytes are pipe traffic, not disk reads. ScannerDiskIO is the macOS proc_pid_rusage disk-byte delta during scanning, excluding children and final report serialization. StageDiskIO attributes scanner-only deltas. Git disk counters are final child lifetime samples, separate from scanner bytes; unmeasured children are counted explicitly. OS-accounted disk bytes are not logical read bytes and are not guaranteed to equal an Activity Monitor sampling window. Available=false means unavailable, not zero. Selection records explicit dependency reasons or the scanner check call chain."
	return &r
}
func (s *Scanner) readDir(path string) ([]os.DirEntry, error) {
	start := time.Now()
	entries, err := os.ReadDir(path)
	if d := s.debug; d != nil {
		d.mu.Lock()
		d.report.Traversal.Calls++
		d.report.Traversal.Entries += int64(len(entries))
		d.report.Traversal.Elapsed += time.Since(start)
		if err != nil {
			d.report.Traversal.Errors++
		}
		d.mu.Unlock()
	}
	return entries, err
}

// Record the actual check call chain instead of inferring a reason from a filename.
func (d *scanDebug) selection(path string) {
	if d == nil {
		return
	}
	pcs := make([]uintptr, 16)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var checks []string
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, ".(*Scanner).") && !strings.Contains(f.Function, ".process") {
			checks = append(checks, f.Function[strings.LastIndex(f.Function, ".")+1:])
		}
		if !more {
			break
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reasons[path] == "" {
		d.reasons[path] = strings.Join(checks, " <- ")
	}
}
