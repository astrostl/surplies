package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

)

var version = "dev"

func main() {
	var (
		jsonOutput bool
		quiet      bool
		showVer    bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "output findings as JSON")
	flag.BoolVar(&quiet, "q", false, "quiet mode (suppress verbose scan details)")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
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

	s := New(homeDir, !quiet)
	findings, stats := s.Run()

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		printFindings(findings, stats)
	}

	// Exit code reflects worst severity
	exitCode := 0
	for _, f := range findings {
		if f.Severity == SevCritical {
			exitCode = 2
			break
		}
		if f.Severity == SevWarn && exitCode < 1 {
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

func printFindings(findings []Finding, stats ScanStats) {
	fmt.Fprintf(os.Stderr, "Stats: %d node_modules (%d pkgs), %d site-packages (%d pkgs), %d files checked\n\n",
		stats.NodeModulesFound, stats.PackagesScanned,
		stats.SitePackagesFound, stats.PythonPackagesScanned,
		stats.FilesChecked)

	if len(findings) == 0 {
		pkgs := make(map[string]bool)
		for pkg := range KnownBadNpmVersions {
			pkgs[pkg] = true
		}
		for pkg := range KnownBadPythonVersions {
			pkgs[pkg] = true
		}
		names := make([]string, 0, len(pkgs))
		for pkg := range pkgs {
			names = append(names, pkg)
		}
		sort.Strings(names)
		fmt.Printf("No supply chain attack indicators found. Checked for: %s.\n", strings.Join(names, ", "))
		return
	}

	critical, warn, info := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case SevCritical:
			critical++
		case SevWarn:
			warn++
		case SevInfo:
			info++
		}
	}

	fmt.Printf("Found %d indicator(s): %d critical, %d warning, %d info\n\n",
		len(findings), critical, warn, info)

	for _, f := range findings {
		marker := " "
		switch f.Severity {
		case SevCritical:
			marker = "!"
		case SevWarn:
			marker = "?"
		}
		fmt.Printf("[%s] %s\n    %s\n    %s\n\n", marker, f.Check, f.Path, f.Detail)
	}
}
