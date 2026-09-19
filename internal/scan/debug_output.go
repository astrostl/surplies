package scan

import (
	"fmt"
	"io"
	"os"
)

func openDebugLog(dir string, quiet bool, terminal io.Writer) (*scanDebug, *os.File, error) {
	f, err := os.CreateTemp(dir, "surplies-debug-*.log")
	if err != nil {
		return nil, nil, err
	}
	var out io.Writer = f
	if !quiet {
		out = io.MultiWriter(f, terminal)
	}
	d := newScanDebug(out)
	d.report.DebugLog = f.Name()
	return d, f, nil
}

// Progress follows the debug destination when enabled. Quiet mode suppresses
// terminal progress, but never drops diagnostics from its debug log.
func (s *Scanner) progress(format string, args ...any) {
	if d := s.debug; d != nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		fmt.Fprintf(d.out, format, args...)
	} else if s.Verbose {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// EnableDebug attaches a debug log to the scanner and returns the open file so
// the caller can close it. Keeps the debug plumbing unexported.
func (s *Scanner) EnableDebug(path string, quiet bool, stderr io.Writer) (*os.File, error) {
	d, f, err := openDebugLog(path, quiet, stderr)
	if err != nil {
		return nil, err
	}
	s.debug = d
	return f, nil
}
