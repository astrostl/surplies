// Package schedule installs, disables and removes a daily surplies scan using
// the platform's user-level scheduler. It is an explicitly invoked management
// command, not part of the scanner: nothing here runs during a scan, and it
// only ever touches its own files. See CLAUDE.md, "Scheduling subcommand".
package schedule

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Scripts carries the embedded notification helpers. The root package owns the
// //go:embed directives because scripts/ lives at the repository root and an
// embed pattern cannot traverse upward out of its own directory.
type Scripts struct {
	Darwin string
	Linux  string
}

type installer struct {
	goos, home, executable, configDir string
	uid                               int
	run                               func(string, ...string) error
	scripts                           Scripts
	roots                             []string
	only                              bool
}

func Command(args []string, out io.Writer, scripts Scripts) error {
	if len(args) > 0 && (args[0] == "disable" || args[0] == "remove") {
		return stopCommand(args, out)
	}
	flags := flag.NewFlagSet("schedule", flag.ContinueOnError)
	flags.SetOutput(out)
	runTime := flags.String("time", "09:00", "daily scan time in local time (24-hour HH:MM)")
	var roots []string
	flags.Func("root", "add/expand a directory to the full scan (repeatable)", func(path string) error {
		roots = append(roots, path)
		return nil
	})
	only := flags.Bool("only", false, "scan only inside the given -root(s) (skips process and network checks)")
	flags.Usage = func() {
		fmt.Fprintln(out, "Usage: surplies schedule [-time HH:MM] [-root DIR ...] [-only]\n       surplies schedule disable\n       surplies schedule remove")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flags.Arg(0))
	}
	hour, minute, err := parseTime(*runTime)
	if err != nil {
		return err
	}
	roots, err = resolveRoots(roots, *only)
	if err != nil {
		return err
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("scheduled scans are supported only on macOS and Linux")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	// Keep the invoked symlink when possible so package-manager upgrades keep working.
	if invoked, lookupErr := exec.LookPath(os.Args[0]); lookupErr == nil {
		executable, err = filepath.Abs(invoked)
		if err != nil {
			return err
		}
	}
	inst := installer{goos: runtime.GOOS, home: home, executable: executable, configDir: os.Getenv("XDG_CONFIG_HOME"), uid: os.Getuid(), run: runTool, scripts: scripts, roots: roots, only: *only}
	if err := inst.install(hour, minute); err != nil {
		return err
	}
	fmt.Fprintf(out, "Daily scans scheduled for %02d:%02d local time. Desktop notifications report nonzero scan results, including incomplete coverage.\n", hour, minute)
	inst.printScope(out)
	return nil
}

func resolveRoots(roots []string, only bool) ([]string, error) {
	if only && len(roots) == 0 {
		return nil, errors.New("-only requires at least one -root")
	}
	resolved := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			return nil, errors.New("scan root must not be empty")
		}
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve -root %s: %w", root, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect -root %s: %w", absolute, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("scan root must be a directory: %s", absolute)
		}
		resolved = append(resolved, absolute)
	}
	return resolved, nil
}

func (s installer) scanCommand(quiet bool) string {
	var command strings.Builder
	command.WriteString(shellQuote(s.executable))
	if quiet {
		command.WriteString(" -q")
	}
	for _, root := range s.roots {
		command.WriteString(" -root " + shellQuote(root))
	}
	if s.only {
		command.WriteString(" -only")
	}
	return command.String()
}

func (s installer) printScope(out io.Writer) {
	if s.only {
		fmt.Fprintln(out, "Scan scope: only the selected directories; a clean result applies only to this scope.")
	} else {
		fmt.Fprintln(out, "Scan scope: default home and machine-wide checks, plus any additional roots.")
	}
	for _, root := range s.roots {
		fmt.Fprintf(out, "  %s\n", root)
	}
	fmt.Fprintf(out, "Run for details: %s\n", s.scanCommand(false))
}

func parseTime(value string) (int, int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || len(value) != 5 {
		return 0, 0, fmt.Errorf("invalid run time %q: use 24-hour HH:MM (for example, 09:00)", value)
	}
	return parsed.Hour(), parsed.Minute(), nil
}

func runTool(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s installer) install(hour, minute int) error {
	if s.goos != "darwin" && s.goos != "linux" {
		return fmt.Errorf("scheduled scans are supported only on macOS and Linux")
	}
	// Fail before writing files if the user's scheduler or notification tool is unavailable.
	if s.goos == "linux" {
		if err := s.run("systemctl", "--user", "show-environment"); err != nil {
			return fmt.Errorf("scheduling requires a running systemd user manager: %w", err)
		}
		if err := s.run("notify-send", "--version"); err != nil {
			return fmt.Errorf("install libnotify (notify-send) for desktop notifications: %w", err)
		}
	}
	script := s.scripts.Darwin
	if s.goos == "linux" {
		script = s.scripts.Linux
	}
	script = strings.NewReplacer(
		"surplies -q", s.scanCommand(true),
		"details_command=surplies", "details_command="+shellQuote(s.scanCommand(false)),
	).Replace(script)
	scriptPath := filepath.Join(s.home, ".local", "bin", "surplies-notify")
	if err := writeFile(scriptPath, script, 0755); err != nil {
		return err
	}
	if s.goos == "darwin" {
		return s.installLaunchAgent(scriptPath, hour, minute)
	}
	return s.installSystemd(scriptPath, hour, minute)
}

func writeFile(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	// Rename a complete file into place; do not follow an existing destination symlink.
	file, err := os.CreateTemp(filepath.Dir(path), ".surplies-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.WriteString(content)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := os.Chmod(file.Name(), mode); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func xmlText(value string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

func (s installer) installLaunchAgent(script string, hour, minute int) error {
	logDir := filepath.Join(s.home, "Library", "Logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	path := filepath.Join(s.home, "Library", "LaunchAgents", "com.surplies.notify.plist")
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.surplies.notify</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>%s</string></array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>%d</integer><key>Minute</key><integer>%d</integer></dict>
<key>StandardOutPath</key><string>%s</string>
<key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, xmlText(script), hour, minute, xmlText(filepath.Join(logDir, "surplies-notify.log")), xmlText(filepath.Join(logDir, "surplies-notify.log")))
	if err := writeFile(path, plist, 0644); err != nil {
		return err
	}
	domain := s.domain()
	service := s.service()
	if err := s.run("launchctl", "print", service); err == nil {
		if err := s.run("launchctl", "bootout", service); err != nil {
			return err
		}
	}
	if err := s.run("launchctl", "enable", service); err != nil {
		return err
	}
	return s.run("launchctl", "bootstrap", domain, path)
}

// domain and service name the launchd GUI domain and the job within it.
func (s installer) domain() string  { return "gui/" + strconv.Itoa(s.uid) }
func (s installer) service() string { return s.domain() + "/com.surplies.notify" }

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "$", "$$")
	return strconv.Quote(value)
}

func (s installer) systemdDir() string {
	config := s.configDir
	if !filepath.IsAbs(config) {
		config = filepath.Join(s.home, ".config")
	}
	return filepath.Join(config, "systemd", "user")
}

func (s installer) installSystemd(script string, hour, minute int) error {
	dir := s.systemdDir()
	service := "[Unit]\nDescription=surplies supply chain scan\n\n[Service]\nType=oneshot\nExecStart=/bin/sh " + systemdQuote(script) + "\n"
	timer := fmt.Sprintf("[Unit]\nDescription=Run surplies daily\n\n[Timer]\nOnCalendar=*-*-* %02d:%02d:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", hour, minute)
	if err := writeFile(filepath.Join(dir, "surplies-notify.service"), service, 0644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "surplies-notify.timer"), timer, 0644); err != nil {
		return err
	}
	if err := s.run("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err := s.run("systemctl", "--user", "enable", "surplies-notify.timer"); err != nil {
		return err
	}
	return s.run("systemctl", "--user", "restart", "surplies-notify.timer")
}

func stopCommand(args []string, out io.Writer) error {
	action := args[0]
	flags := flag.NewFlagSet("schedule "+action, flag.ContinueOnError)
	flags.SetOutput(out)
	flags.Usage = func() { fmt.Fprintf(out, "Usage: surplies schedule %s\n", action) }
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flags.Arg(0))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	inst := installer{goos: runtime.GOOS, home: home, configDir: os.Getenv("XDG_CONFIG_HOME"), uid: os.Getuid(), run: runTool}
	if action == "remove" {
		if err := inst.remove(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Schedule and notification helper removed. The surplies binary and scan logs were kept.")
	} else {
		if err := inst.disable(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Schedule disabled. Installed files were kept. Run 'surplies schedule [-time HH:MM] [-root DIR ...] [-only]' to enable daily scans again. Omitted settings revert to defaults (09:00, full scope).")
	}
	return nil
}

func (s installer) disable() error {
	switch s.goos {
	case "darwin":
		service := s.service()
		if err := s.run("launchctl", "disable", service); err != nil {
			return err
		}
		// An unloaded job is already stopped; other failures must remain visible.
		err := s.run("launchctl", "bootout", service)
		var status interface{ ExitCode() int }
		if errors.As(err, &status) && status.ExitCode() == 3 {
			return nil
		}
		return err
	case "linux":
		if err := s.run("systemctl", "--user", "disable", "--now", "surplies-notify.timer"); err != nil {
			return err
		}
		return s.run("systemctl", "--user", "stop", "surplies-notify.service")
	default:
		return fmt.Errorf("scheduled scans are supported only on macOS and Linux")
	}
}

func (s installer) remove() error {
	if err := s.disable(); err != nil {
		return err
	}
	var paths []string
	if s.goos == "darwin" {
		paths = []string{filepath.Join(s.home, "Library", "LaunchAgents", "com.surplies.notify.plist")}
	} else {
		paths = []string{filepath.Join(s.systemdDir(), "surplies-notify.timer"), filepath.Join(s.systemdDir(), "surplies-notify.service")}
	}
	paths = append(paths, filepath.Join(s.home, ".local", "bin", "surplies-notify"))
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if s.goos == "linux" {
		return s.run("systemctl", "--user", "daemon-reload")
	}
	// disable() wrote a persistent launchd override. Clear it now that the job
	// is unloaded and the plist is gone, so removal does not leave an orphan
	// "disabled" entry behind for a service that no longer exists. The plist is
	// already deleted, so this only clears the override; it cannot load anything.
	return s.run("launchctl", "enable", s.service())
}
