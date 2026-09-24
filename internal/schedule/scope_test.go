package schedule

import (
	"bytes"
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

func TestScheduleRoots(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-only"}, {"-root", ""}, {"-root", " "},
		{"-root", file}, {"-root", filepath.Join(dir, "missing")},
		{"-root", dir, "-root", file, "-only"},
	} {
		if err := Command(args, io.Discard, testScripts(t)); err == nil {
			t.Fatalf("accepted invalid scope %v", args)
		}
	}
	t.Chdir(dir)
	roots, err := resolveRoots([]string{".", dir}, true)
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roots, []string{cwd, dir}) {
		t.Fatalf("roots: %v", roots)
	}
}

func TestScheduledScopeReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX shell")
	}
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			capture := filepath.Join(home, "arguments")
			binary := filepath.Join(home, "scan ' $HOME; & executable")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\000' \"$@\" >\"$CAPTURE\"\nexit \"$SCAN_EXIT\"\n"), 0755); err != nil {
				t.Fatal(err)
			}
			for _, notifier := range []string{"osascript", "notify-send"} {
				if err := os.WriteFile(filepath.Join(home, notifier), []byte("#!/bin/sh\nprintf 'CALL\\n'\nprintf '%s\\000' \"$@\"\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			roots := []string{filepath.Join(home, "tree ' \" $HOME $(exit 88) `exit 89`; & %"), filepath.Join(home, "surplies -q details_command=surplies")}
			for _, root := range roots {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			inst := installer{goos: goos, home: home, executable: binary, scripts: testScripts(t), run: func(string, ...string) error { return nil }}
			for _, scope := range []struct {
				roots []string
				only  bool
			}{
				{roots, true}, {roots[1:], false}, {nil, false},
			} {
				inst.roots, inst.only = scope.roots, scope.only
				if err := inst.install(9, 0); err != nil {
					t.Fatal(err)
				}
				want := []string{"-q"}
				for _, root := range scope.roots {
					want = append(want, "-root", root)
				}
				if scope.only {
					want = append(want, "-only")
				}
				checkScopedNotifications(t, inst, capture, want)
				var summary bytes.Buffer
				inst.printScope(&summary)
				if !strings.Contains(summary.String(), inst.scanCommand(false)) {
					t.Fatalf("missing manual command: %s", summary.String())
				}
				cmd := exec.Command("/bin/sh", "-c", inst.scanCommand(false))
				cmd.Env = append(os.Environ(), "CAPTURE="+capture, "SCAN_EXIT=0")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("manual command: %s: %v", output, err)
				}
				assertScanArguments(t, capture, want[1:])
			}
		})
	}
}

func checkScopedNotifications(t *testing.T, inst installer, capture string, want []string) {
	t.Helper()
	for _, code := range []int{0, 1, 2, 3, 127} {
		cmd := exec.Command("/bin/sh", filepath.Join(inst.home, ".local", "bin", "surplies-notify"))
		cmd.Env = append(os.Environ(), "PATH="+inst.home, "CAPTURE="+capture, fmt.Sprintf("SCAN_EXIT=%d", code))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %s: %v", output, err)
		}
		assertScanArguments(t, capture, want)
		if code == 0 {
			if len(output) != 0 {
				t.Fatalf("clean scan notified: %s", output)
			}
			continue
		}
		checkNotifierArguments(t, inst.goos, code, output)
		message := "Run for details: " + inst.scanCommand(false)
		if !strings.Contains(string(output), message) {
			t.Fatalf("notification lacks scoped command: %s", output)
		}
	}
}

func assertScanArguments(t *testing.T, path string, want []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := strings.Join(want, "\x00") + "\x00"
	if string(data) != wantBytes {
		t.Fatalf("arguments: got %q, want %q", data, wantBytes)
	}
}

func checkNotifierArguments(t *testing.T, goos string, code int, output []byte) {
	t.Helper()
	text := string(output)
	if strings.Count(text, "CALL\n") != 1 {
		t.Fatalf("expected one notification, got %q", text)
	}
	args := strings.Split(strings.TrimSuffix(strings.TrimPrefix(text, "CALL\n"), "\x00"), "\x00")
	title, urgency := "Surplies: Warning", "normal"
	if code == 2 {
		title, urgency = "Surplies: Critical", "critical"
	}
	if goos == "linux" {
		if len(args) != 4 || args[0] != "-u" || args[1] != urgency || args[2] != title {
			t.Fatalf("invalid notification arguments: %q", args)
		}
		return
	}
	if len(args) < 2 || args[len(args)-2] != title {
		t.Fatalf("invalid notification title: %q", args)
	}
	if strings.Contains(text, "sound name") != (code == 2) {
		t.Fatalf("wrong sound for exit %d: %q", code, args)
	}
}
