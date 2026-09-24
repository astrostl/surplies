package scan

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// A running process is checked against indicators the scanner already holds
// on disk: Node executing a font-extension file (the folderOpen task's
// command, now running), a *.inz.cjs / *.inz.orig sidecar on a command line,
// and the script a Node process runs matched against the payload hash and
// signature lists. No new IOC is introduced here.
// https://github.com/OpenSourceMalware/PolinRider
// https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
//
// Command lines are read through operating-system process interfaces
// (/proc, sysctl, the Windows process APIs); no external command is run.

type processInfo struct {
	PID  int
	Exe  string
	Args []string
	// Cwd resolves a relative script argument. Empty where the platform or
	// the process's owner does not expose it.
	Cwd string
}

type processSnapshot struct {
	procs []processInfo
	// restricted counts processes whose command line this account may not
	// read: other users' processes on macOS, protected ones on Windows.
	restricted int
}

type processCollector func() (processSnapshot, error)

func (s *Scanner) checkProcesses() {
	s.inspectProcesses(listProcesses)
}

func (s *Scanner) inspectProcesses(collect processCollector) {
	snap, err := collect()
	if err != nil {
		s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: "processes", coverageCategory: "process collection",
			Detail: fmt.Sprintf("Process collection failed: %v; running-process coverage is incomplete", err)})
		return
	}
	self := os.Getpid()
	// This process is always running and always readable by its own account,
	// so a snapshot without it means the collector saw nothing it should have.
	if !slices.ContainsFunc(snap.procs, func(p processInfo) bool { return p.PID == self }) {
		s.addFinding(Finding{Check: "scan-incomplete", Severity: SevWarn, Path: "processes", coverageCategory: "process collection",
			Detail: fmt.Sprintf("Process collection returned %d readable processes and not this scanner's own; running-process coverage is incomplete", len(snap.procs))})
	}
	unresolved := 0
	for _, p := range sortedProcesses(snap.procs) {
		if p.PID == self || len(p.Args) == 0 {
			continue
		}
		if !s.inspectProcess(p) {
			unresolved++
		}
	}
	if snap.restricted > 0 {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: "processes",
			Detail: fmt.Sprintf("%d running processes owned by other users or protected by the system could not be read from this account, so their command lines were not checked. Run as root or administrator to include them", snap.restricted)})
	}
	if unresolved > 0 {
		s.addFinding(Finding{Check: "scan-limited", Severity: SevInfo, Path: "processes",
			Detail: fmt.Sprintf("%d Node processes run a relative script path whose working directory could not be read, so those scripts were checked by name only, not hashed", unresolved)})
	}
}

// inspectProcess reports false only when a Node script could not be located
// for hashing; every other outcome, including a clean process, is true.
func (s *Scanner) inspectProcess(p processInfo) bool {
	var reasons []string
	target := ""
	for _, arg := range p.Args {
		if sidecar := sidecarArgument(arg); sidecar != "" {
			reasons = append(reasons, fmt.Sprintf("its command line names the injection sidecar %s (attack: polinrider (DPRK))", sidecar))
			target = processPath(p, sidecar)
			break
		}
	}
	located := true
	if nodeExecutable(p.Args[0]) || (p.Exe != "" && nodeExecutable(p.Exe)) {
		if script, ok := nodeScriptArgument(p.Args[1:]); ok {
			path := processPath(p, script)
			located = filepath.IsAbs(path)
			if slices.Contains(fontExtensions, strings.ToLower(filepath.Ext(script))) {
				reasons = append(reasons, fmt.Sprintf("Node is executing the font-extension file %s (attack: polinrider (DPRK))", script))
				target = path
			}
			if located {
				if data := s.processFileMode(path, ReadTimeout, nil, true); data != nil {
					if match := runningScriptMatch(filepath.Base(path), data); match != "" {
						reasons = append(reasons, match)
						target = path
					}
				}
			}
		}
	}
	if len(reasons) == 0 {
		return located
	}
	cause := "A running process matches a known payload indicator:"
	evidence := fmt.Sprintf("PID %d (%s): %s", p.PID, filepath.Base(p.Args[0]), strings.Join(reasons, "; "))
	s.addFinding(Finding{Check: "running-payload-process", Severity: SevCritical, Path: target,
		cause: cause, evidence: evidence, Detail: cause + " " + evidence})
	return located
}

// processPath resolves an argument against the process's working directory,
// returning it unchanged where that directory is unknown.
func processPath(p processInfo, arg string) string {
	if filepath.IsAbs(arg) || p.Cwd == "" {
		return arg
	}
	return filepath.Join(p.Cwd, arg)
}

// sidecarArgument returns the sidecar path an argument names, if any. The
// value of an --opt=value form is checked, and glob patterns (a find or grep
// looking for sidecars) are not a sidecar being loaded.
func sidecarArgument(arg string) string {
	if i := strings.LastIndex(arg, "="); i >= 0 {
		arg = arg[i+1:]
	}
	arg = strings.Trim(arg, `"'`)
	if strings.ContainsAny(arg, "*?[") || strings.Contains(arg, `\.`) {
		return ""
	}
	if isPersistenceSidecar(strings.ToLower(arg)) {
		return arg
	}
	return ""
}

// nodeValueOptions consume the next argument, which is therefore not the
// script. -e/-p and stdin carry their program inline, so there is no file.
var nodeValueOptions = []string{"-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type", "--title", "--env-file"}
var nodeInlineOptions = []string{"-e", "--eval", "-p", "--print", "-"}

func nodeScriptArgument(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case slices.Contains(nodeInlineOptions, arg) || arg == "-pe":
			return "", false
		case slices.Contains(nodeValueOptions, arg):
			i++
		case strings.HasPrefix(arg, "-"):
		default:
			return arg, true
		}
	}
	return "", false
}

// runningScriptMatch applies the identity checks to the bytes of a script a
// process is running: exact payload hashes, published signatures, and the
// config-append span carved from behind its padding.
func runningScriptMatch(name string, data []byte) string {
	size := int64(len(data))
	if knownPayloadName(name) || knownPayloadSize(size) {
		digest := fmt.Sprintf("%x", sha256.Sum256(data))
		for _, h := range KnownRepoPayloadHashes {
			if (name == h.Filename || (h.Size != 0 && h.Size == size)) && digest == h.SHA256 {
				return fmt.Sprintf("the script's SHA-256 matches %s (attack: %s)", h.Desc, h.Attack)
			}
		}
	}
	if sig, ok := payloadSignature(normalizeASCII(data)); ok {
		return fmt.Sprintf("the script contains %s (attack: %s)", sig.Desc, sig.Attack)
	}
	if h, n, ok := paddedPayloadHash(data); ok {
		return fmt.Sprintf("the script carries %s as a %d-byte span behind a whitespace run (attack: %s)", h.Desc, n, h.Attack)
	}
	return ""
}

// sortedProcesses orders a snapshot by PID so findings print deterministically.
func sortedProcesses(procs []processInfo) []processInfo {
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs
}
