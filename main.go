package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/astrostl/surplies/internal/scan"
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
	var (
		jsonOutput bool
		quiet      bool
		showVer    bool
		extraRoots []string
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
	flag.Usage = printUsage
	flag.Parse()

	if showVer {
		fmt.Printf("surplies %s\n", version)
		os.Exit(0)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}

	s := scan.New(homeDir, !quiet)
	s.Deep = modes.Deep
	s.Git = modes.Git
	s.NpmCache = modes.NpmCache
	s.Broad = modes.Broad
	s.BrowserCache = modes.BrowserCache
	var debugLog *os.File
	if modes.Debug {
		debugLog, err = s.EnableDebug("", quiet, os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not create debug log: %v\n", err)
			os.Exit(1)
		}
	}
	s.ExtraRoots = extraRoots
	findings, stats := s.Run()
	if debugLog != nil {
		if err := debugLog.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Could not close debug log: %v\n", err)
		}
	}

	invocation := scan.InvocationLabel(version, os.Args[1:])
	scan.PrintResults(findings, stats, jsonOutput, modes.Coverage, invocation)

	// Exit code reflects worst severity
	exitCode := 0
	for _, f := range findings {
		if f.Severity == scan.SevCritical {
			exitCode = 2
			break
		}
		if f.Severity == scan.SevWarn && exitCode < 1 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "surplies %s\n\n", version)
	fmt.Fprintln(out, "Usage: surplies [flags]")
	fmt.Fprintln(out)
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
