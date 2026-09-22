package schedule

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestScheduleTime(t *testing.T) {
	for _, value := range []string{"09:00", "00:00", "23:59", "12:30"} {
		h, m, err := parseTime(value)
		if err != nil || fmt.Sprintf("%02d:%02d", h, m) != value {
			t.Fatalf("%q: %d:%d, %v", value, h, m, err)
		}
	}
	for _, value := range []string{"9:00", "24:00", "09:60", "9am", "09:00:00", "", " 09:00", "-1:00"} {
		if _, _, err := parseTime(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestScheduleCommandRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"-time", "25:00"}, {"extra"}, {"-deep"}, {"disable", "-time", "09:00"}, {"remove", "extra"}} {
		if err := Command(args, io.Discard, testScripts(t)); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	var out bytes.Buffer
	if err := Command([]string{"-help"}, &out, testScripts(t)); err == nil || !strings.Contains(out.String(), "09:00") {
		t.Fatalf("missing help: %s, %v", out.String(), err)
	}
}

func TestScheduleInstallation(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "user & spaces")
			var calls []string
			inst := installer{goos: goos, home: home, executable: "/apps/Surplies & tools/surplies", uid: 123, scripts: testScripts(t), run: func(name string, args ...string) error {
				calls = append(calls, name+" "+strings.Join(args, " "))
				return nil
			}}
			for _, hour := range []int{9, 17} {
				calls = nil
				if err := inst.install(hour, 30); err != nil {
					t.Fatal(err)
				}
				script := filepath.Join(home, ".local", "bin", "surplies-notify")
				data, err := os.ReadFile(script)
				if err != nil || !strings.Contains(string(data), "'/apps/Surplies & tools/surplies' -q") {
					t.Fatalf("script: %s, %v", data, err)
				}
				info, err := os.Stat(script)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("script mode: %v, %v", info, err)
				}
				if goos == "darwin" {
					checkLaunchAgent(t, home, hour, calls)
				} else {
					checkSystemdSchedule(t, home, script, hour, calls)
				}
			}
		})
	}
}

func TestSchedulePrerequisiteFailure(t *testing.T) {
	for _, failTool := range []string{"systemctl", "notify-send"} {
		home := t.TempDir()
		inst := installer{goos: "linux", home: home, scripts: testScripts(t), run: func(name string, _ ...string) error {
			if name == failTool {
				return errors.New("unavailable")
			}
			return nil
		}}
		if err := inst.install(9, 0); err == nil {
			t.Fatal("missing error")
		}
		entries, _ := os.ReadDir(home)
		if len(entries) != 0 {
			t.Fatal("wrote files before prerequisite check")
		}
	}
	inst := installer{goos: "windows"}
	if err := inst.install(9, 0); err == nil {
		t.Fatal("accepted unsupported platform")
	}
}

func TestScheduleActivationFailure(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		failure := errors.New("activation failed")
		inst := installer{goos: goos, home: t.TempDir(), executable: "/bin/surplies", scripts: testScripts(t), run: func(name string, args ...string) error {
			if args[0] == "bootstrap" || (len(args) > 1 && args[1] == "restart") {
				return failure
			}
			return nil
		}}
		if err := inst.install(9, 0); !errors.Is(err, failure) {
			t.Fatalf("activation error lost: %v", err)
		}
	}
}

func TestSystemdConfigAndEscaping(t *testing.T) {
	if got := systemdQuote(`/home/a%u/$USER/"scan"`); got != `"/home/a%%u/$$USER/\"scan\""` {
		t.Fatal(got)
	}
	inst := installer{goos: "linux", home: t.TempDir(), configDir: t.TempDir(), scripts: testScripts(t), run: func(string, ...string) error { return nil }}
	if err := inst.install(9, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(inst.configDir, "systemd", "user", "surplies-notify.timer")); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledNotificationScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX shell")
	}
	for _, goos := range []string{"darwin", "linux"} {
		for _, code := range []int{0, 1, 2, 3, 127} {
			t.Run(fmt.Sprintf("%s/%d", goos, code), func(t *testing.T) {
				home := t.TempDir()
				binary := filepath.Join(home, "scan ' $HOME; & executable")
				if err := os.WriteFile(binary, fmt.Appendf(nil, "#!/bin/sh\n[ \"$1\" = -q ] || exit 99\nexit %d\n", code), 0755); err != nil {
					t.Fatal(err)
				}
				for _, notifier := range []string{"osascript", "notify-send"} {
					if err := os.WriteFile(filepath.Join(home, notifier), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0755); err != nil {
						t.Fatal(err)
					}
				}
				inst := installer{goos: goos, home: home, executable: binary, scripts: testScripts(t), run: func(string, ...string) error { return nil }}
				if err := inst.install(9, 0); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("/bin/sh", filepath.Join(home, ".local", "bin", "surplies-notify"))
				cmd.Env = append(os.Environ(), "PATH="+home)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%s: %v", output, err)
				}
				checkNotificationOutput(t, code, output)
			})
		}
	}
}

func checkNotificationOutput(t *testing.T, code int, output []byte) {
	t.Helper()
	text := string(output)
	if code == 0 && len(output) != 0 {
		t.Fatalf("clean scan notified: %s", output)
	}
	if code == 2 && (!strings.Contains(text, "Surplies: Critical") || !strings.Contains(text, "Critical supply chain attack indicators, or a scan whose coverage failed")) {
		t.Fatalf("no critical notification: %s", output)
	}
	if code != 0 && code != 2 && (!strings.Contains(text, "Surplies: Warning") || !strings.Contains(text, "warnings, incomplete coverage, or an error")) {
		t.Fatalf("wrong warning notification for exit %d: %s", code, output)
	}
	if code != 2 && strings.Contains(text, "Critical") {
		t.Fatalf("exit %d produced a critical notification: %s", code, output)
	}
}

func checkLaunchAgent(t *testing.T, home string, hour int, calls []string) {
	t.Helper()
	path := filepath.Join(home, "Library", "LaunchAgents", "com.surplies.notify.plist")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(string(data), fmt.Sprintf("<integer>%d</integer>", hour)) || !strings.Contains(string(data), "user &amp; spaces") {
		t.Fatalf("bad plist: %s", data)
	}
	want := []string{"launchctl print gui/123/com.surplies.notify", "launchctl bootout gui/123/com.surplies.notify", "launchctl enable gui/123/com.surplies.notify", "launchctl bootstrap gui/123 " + path}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls: %v", calls)
	}

}

func checkSystemdSchedule(t *testing.T, home, script string, hour int, calls []string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "systemd", "user")
	data, err := os.ReadFile(filepath.Join(dir, "surplies-notify.timer"))
	if err != nil || !strings.Contains(string(data), fmt.Sprintf("OnCalendar=*-*-* %02d:30:00", hour)) {
		t.Fatalf("timer: %s, %v", data, err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "surplies-notify.service"))
	if err != nil || !strings.Contains(string(data), "ExecStart=/bin/sh "+systemdQuote(script)) {
		t.Fatalf("service: %s, %v", data, err)
	}
	want := []string{"systemctl --user show-environment", "notify-send --version", "systemctl --user daemon-reload", "systemctl --user enable surplies-notify.timer", "systemctl --user restart surplies-notify.timer"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls: %v", calls)
	}
}

func TestScheduleDisableKeepsFiles(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			var calls []string
			inst := installer{goos: goos, home: t.TempDir(), uid: 123, scripts: testScripts(t), run: func(name string, args ...string) error {
				calls = append(calls, name+" "+strings.Join(args, " "))
				return nil
			}}
			if err := inst.install(14, 30); err != nil {
				t.Fatal(err)
			}
			before := installedFiles(t, inst.home)
			calls = nil
			if err := inst.disable(); err != nil {
				t.Fatal(err)
			}
			if after := installedFiles(t, inst.home); !reflect.DeepEqual(before, after) {
				t.Fatal("disable changed installed files")
			}
			want := []string{"launchctl disable gui/123/com.surplies.notify", "launchctl bootout gui/123/com.surplies.notify"}
			if goos == "linux" {
				want = []string{"systemctl --user disable --now surplies-notify.timer", "systemctl --user stop surplies-notify.service"}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls: %v", calls)
			}
		})
	}
}

func installedFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		files[path] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestScheduleRemoveKeepsUnrelatedFiles(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			inst := installer{goos: goos, home: t.TempDir(), scripts: testScripts(t), run: func(string, ...string) error { return nil }}
			inst.configDir = filepath.Join(inst.home, "custom-config")
			keep := filepath.Join(inst.home, "keep")
			if err := os.WriteFile(keep, []byte("preserve me"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := inst.install(9, 0); err != nil {
				t.Fatal(err)
			}
			if err := inst.remove(); err != nil {
				t.Fatal(err)
			}
			if files := installedFiles(t, inst.home); !reflect.DeepEqual(files, map[string]string{keep: "preserve me"}) {
				t.Fatalf("remaining files: %v", files)
			}
		})
	}
}

func TestRemoveClearsLaunchdDisableOverride(t *testing.T) {
	var calls []string
	inst := installer{goos: "darwin", home: t.TempDir(), uid: 123, scripts: testScripts(t), run: func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}}
	if err := inst.install(9, 0); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := inst.remove(); err != nil {
		t.Fatal(err)
	}
	// disable() writes a persistent override; remove() must clear it last, once
	// the job is unloaded and the plist is gone. Otherwise launchd keeps a
	// "disabled" entry for a service that no longer exists.
	want := []string{
		"launchctl disable gui/123/com.surplies.notify",
		"launchctl bootout gui/123/com.surplies.notify",
		"launchctl enable gui/123/com.surplies.notify",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls: %v", calls)
	}
}

func TestDisableKeepsLaunchdOverride(t *testing.T) {
	var calls []string
	inst := installer{goos: "darwin", home: t.TempDir(), uid: 123, scripts: testScripts(t), run: func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}}
	if err := inst.disable(); err != nil {
		t.Fatal(err)
	}
	// disable() must NOT re-enable; the override is what makes it persist.
	for _, call := range calls {
		if strings.Contains(call, "enable") {
			t.Fatalf("disable re-enabled the job: %v", calls)
		}
	}
}

func TestScheduleRemoveStopsOnSchedulerError(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		inst := installer{goos: goos, home: t.TempDir(), scripts: testScripts(t), run: func(string, ...string) error { return nil }}
		if err := inst.install(9, 0); err != nil {
			t.Fatal(err)
		}
		before := installedFiles(t, inst.home)
		failure := errors.New("scheduler unavailable")
		inst.run = func(string, ...string) error { return failure }
		if err := inst.remove(); !errors.Is(err, failure) {
			t.Fatalf("missing error: %v", err)
		}
		if after := installedFiles(t, inst.home); !reflect.DeepEqual(before, after) {
			t.Fatal("removed files after scheduler failure")
		}
	}
}

type exitError int

func (s exitError) Error() string { return "scheduler exit" }
func (s exitError) ExitCode() int { return int(s) }

func TestDisableUnloadedLaunchAgent(t *testing.T) {
	for _, code := range []int{3, 5} {
		inst := installer{goos: "darwin", scripts: testScripts(t), run: func(_ string, args ...string) error {
			if args[0] == "bootout" {
				return fmt.Errorf("bootout: %w", exitError(code))
			}
			return nil
		}}
		err := inst.disable()
		if (err == nil) != (code == 3) {
			t.Fatalf("exit %d: %v", code, err)
		}
	}
}

// testScripts loads the real notification helpers from the repository root.
// The root package owns the //go:embed directives, so this package reads the
// same files from disk rather than duplicating them as fixtures.
func testScripts(t *testing.T) Scripts {
	t.Helper()
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "notify", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	return Scripts{Darwin: read("macos.sh"), Linux: read("linux.sh")}
}
