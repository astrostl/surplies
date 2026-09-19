package main

import (
	"bytes"
	_ "embed"
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

//go:embed scripts/notify/macos.sh
var macNotify string

//go:embed scripts/notify/linux.sh
var linuxNotify string

type scheduleInstaller struct {
	goos, home, executable, configDir string
	uid                               int
	run                               func(string, ...string) error
}

func scheduleCommand(args []string, out io.Writer) error {
	if len(args) > 0 && (args[0] == "disable" || args[0] == "remove") {
		return scheduleStopCommand(args, out)
	}
	flags := flag.NewFlagSet("schedule", flag.ContinueOnError)
	flags.SetOutput(out)
	runTime := flags.String("time", "09:00", "daily scan time in local time (24-hour HH:MM)")
	flags.Usage = func() {
		fmt.Fprintln(out, "Usage: surplies schedule [-time HH:MM]\n       surplies schedule disable\n       surplies schedule remove")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flags.Arg(0))
	}
	hour, minute, err := parseScheduleTime(*runTime)
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
	installer := scheduleInstaller{goos: runtime.GOOS, home: home, executable: executable, configDir: os.Getenv("XDG_CONFIG_HOME"), uid: os.Getuid(), run: runScheduleTool}
	if err := installer.install(hour, minute); err != nil {
		return err
	}
	fmt.Fprintf(out, "Daily scans scheduled for %02d:%02d local time. Desktop notifications report nonzero scan results, including incomplete coverage.\n", hour, minute)
	return nil
}

func parseScheduleTime(value string) (int, int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || len(value) != 5 {
		return 0, 0, fmt.Errorf("invalid run time %q: use 24-hour HH:MM (for example, 09:00)", value)
	}
	return parsed.Hour(), parsed.Minute(), nil
}

func runScheduleTool(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s scheduleInstaller) install(hour, minute int) error {
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
	script := macNotify
	if s.goos == "linux" {
		script = linuxNotify
	}
	script = strings.Replace(script, "surplies -q", shellQuote(s.executable)+" -q", 1)
	scriptPath := filepath.Join(s.home, ".local", "bin", "surplies-notify")
	if err := writeScheduleFile(scriptPath, script, 0755); err != nil {
		return err
	}
	if s.goos == "darwin" {
		return s.installLaunchAgent(scriptPath, hour, minute)
	}
	return s.installSystemd(scriptPath, hour, minute)
}

func writeScheduleFile(path, content string, mode os.FileMode) error {
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

func (s scheduleInstaller) installLaunchAgent(script string, hour, minute int) error {
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
	if err := writeScheduleFile(path, plist, 0644); err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(s.uid)
	service := domain + "/com.surplies.notify"
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

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "$", "$$")
	return strconv.Quote(value)
}

func (s scheduleInstaller) systemdDir() string {
	config := s.configDir
	if !filepath.IsAbs(config) {
		config = filepath.Join(s.home, ".config")
	}
	return filepath.Join(config, "systemd", "user")
}

func (s scheduleInstaller) installSystemd(script string, hour, minute int) error {
	dir := s.systemdDir()
	service := "[Unit]\nDescription=surplies supply chain scan\n\n[Service]\nType=oneshot\nExecStart=/bin/sh " + systemdQuote(script) + "\n"
	timer := fmt.Sprintf("[Unit]\nDescription=Run surplies daily\n\n[Timer]\nOnCalendar=*-*-* %02d:%02d:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", hour, minute)
	if err := writeScheduleFile(filepath.Join(dir, "surplies-notify.service"), service, 0644); err != nil {
		return err
	}
	if err := writeScheduleFile(filepath.Join(dir, "surplies-notify.timer"), timer, 0644); err != nil {
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

func scheduleStopCommand(args []string, out io.Writer) error {
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
	installer := scheduleInstaller{goos: runtime.GOOS, home: home, configDir: os.Getenv("XDG_CONFIG_HOME"), uid: os.Getuid(), run: runScheduleTool}
	if action == "remove" {
		if err := installer.remove(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Schedule and notification helper removed. The surplies binary and scan logs were kept.")
	} else {
		if err := installer.disable(); err != nil {
			return err
		}
		fmt.Fprintln(out, "Schedule disabled. Installed files were kept. Run 'surplies schedule [-time HH:MM]' to enable daily scans again (default: 09:00).")
	}
	return nil
}

func (s scheduleInstaller) disable() error {
	switch s.goos {
	case "darwin":
		service := "gui/" + strconv.Itoa(s.uid) + "/com.surplies.notify"
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

func (s scheduleInstaller) remove() error {
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
	return nil
}
