package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/astrostl/surplies/internal/scan"
	"github.com/astrostl/surplies/internal/schedule"
)

var version = "dev"

func init() {
	if version != "dev" {
		return // ldflags already set it
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
}

func main() {
	// The schedule subcommand is dispatched before flag parsing so its own flag
	// set owns everything after the verb. It never scans.
	if len(os.Args) > 1 && os.Args[1] == "schedule" {
		if err := schedule.Command(os.Args[2:], os.Stdout, notifyScripts()); err != nil && !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(runScan())
}

// runScan parses the scan flags, runs the scan and returns the process exit
// code. It is separate from main so the subcommand dispatch above stays a
// dispatch and neither half inflates the other's cyclomatic complexity.
func runScan() int {
	var (
		jsonOutput bool
		quiet      bool
		showVer    bool
		extraRoots []string
		only       bool
		noPause    bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&quiet, "q", false, "suppress scan details")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.BoolVar(&showVer, "v", false, "") // undocumented -v/--v alias
	modes := scan.RegisterScanModes(flag.CommandLine)
	flag.Func("root", "add/expand a directory to the full scan (repeatable)", func(path string) error {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("scan root must not be empty")
		}
		extraRoots = append(extraRoots, path)
		return nil
	})
	flag.BoolVar(&only, "only", false, "scan only inside the given -root(s) (skips process and network checks)")
	flag.BoolVar(&noPause, "no-pause", false, "never wait for ENTER before exiting (Windows only, "+PauseDisabledEnv+" equivalent)")
	flag.Usage = printUsage
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument: %s\n", flag.Arg(0))
		return 1
	}

	if showVer {
		fmt.Printf("surplies %s\n", version)
		return 0
	}

	homeDir, extraRoots, err := resolveScanScope(only, extraRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		if only && len(extraRoots) == 0 {
			printUsage()
		}
		return 1
	}

	invocation := scan.InvocationLabel(version, os.Args[1:])
	s := scan.New(homeDir, !quiet)
	s.Invocation = invocation
	s.Only = only
	s.Deep = modes.Deep
	s.Git = modes.Git
	s.NpmCache = modes.NpmCache
	s.Broad = modes.Broad
	s.BrowserCache = modes.BrowserCache
	s.Resolve = modes.Resolve
	var debugLog *os.File
	if modes.Debug {
		debugLog, err = s.EnableDebug("", quiet, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create debug log: %v\n", err)
			return 1
		}
	}
	s.ExtraRoots = extraRoots
	s.TempRoots = scan.DefaultTempRoots()
	s.SkipTempRoots = modes.SkipTempRoots
	findings, stats := s.Run()
	if debugLog != nil {
		if err := debugLog.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Could not close debug log: %v\n", err)
		}
	}

	scan.PrintResults(findings, stats, jsonOutput, modes.Coverage, invocation)

	// Last thing before the exit code, so a double-clicked run's window stays
	// up over the whole report rather than closing on top of it.
	if shouldPauseForLauncherWindow(noPause) {
		pauseForLauncherWindow(os.Stdout, os.Stdin, launcherWindowPauseTimeout)
	}
	return worstSeverityExitCode(findings)
}

// worstSeverityExitCode maps findings to the process exit code the notify
// scripts key on: 2 critical, 1 warning, 0 clean.
func worstSeverityExitCode(findings []scan.Finding) int {
	exitCode := 0
	for _, f := range findings {
		if f.Severity == scan.SevCritical {
			return 2
		}
		if f.Severity == scan.SevWarn {
			exitCode = 1
		}
	}
	return exitCode
}

// resolveScanScope returns the root the walks are anchored at plus any extra
// roots. Without -only that is the home directory. With it, -only narrows
// -root rather than naming its own directory, so the first -root takes home's
// place and the rest stay extra: every walk then sits inside what the user
// asked for, and nothing silently falls back to scanning home.
func resolveScanScope(only bool, roots []string) (string, []string, error) {
	if !only {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", nil, fmt.Errorf("cannot determine home directory: %w", err)
		}
		return home, roots, nil
	}
	if len(roots) == 0 {
		return "", nil, errors.New("-only requires at least one -root")
	}
	abs, err := filepath.Abs(roots[0])
	if err != nil {
		return "", nil, fmt.Errorf("cannot resolve -root %s: %w", roots[0], err)
	}
	if info, statErr := os.Stat(abs); statErr != nil || !info.IsDir() {
		return "", nil, fmt.Errorf("-only requires an existing directory: %s", abs)
	}
	return abs, roots[1:], nil
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "surplies %s\n\n", version)
	fmt.Fprintln(out, "Scan this machine for supply-chain compromise indicators. Reports only and changes nothing.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  surplies [flags]                  scan now")
	fmt.Fprintln(out, "  surplies schedule [options]       schedule a daily scan + notification (default 09:00)")
	fmt.Fprintln(out, "  surplies schedule disable|remove  turn off the daily scan")
	fmt.Fprintln(out)
	// The flags below belong to the scan, not to `schedule`. Naming the
	// section says so; an unlabelled list under a sentence about scheduling
	// read as though -broad and -root were options to that subcommand.
	fmt.Fprintln(out, "Scan flags:")
	flag.VisitAll(func(f *flag.Flag) {
		name := f.Name
		if name == "v" {
			return
		}
		if name == "root" {
			name += " value"
		}
		fmt.Fprintf(out, "  -%s\n        %s\n", name, f.Usage)
	})
	fmt.Fprintln(out)
	fmt.Fprintln(out, scan.DefaultScanHelp(runtime.GOOS, scan.DefaultPersistenceRoots()))
}

// Expected scope limits stay visible but are neither collection failures nor
// attack indicators. JSON retains these INFO records; they do not change exit status.
