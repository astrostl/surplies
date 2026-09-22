package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ENTER releases the wait immediately; the timeout releases it without one.
// Both paths have to end, because the alternative is a scanner that never
// exits on a machine nobody is sitting at.
func TestPauseForLauncherWindowEndsOnInputOrTimeout(t *testing.T) {
	for _, c := range []struct {
		name    string
		input   string
		timeout time.Duration
	}{
		{"enter", "\n", time.Minute},
		{"closed input", "", time.Minute},
		{"nobody typed", strings.Repeat("x", 4096), 10 * time.Millisecond},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out strings.Builder
			done := make(chan struct{})
			go func() {
				defer close(done)
				pauseForLauncherWindow(&out, strings.NewReader(c.input), c.timeout)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("pause never returned")
			}
			if !strings.Contains(out.String(), "Press ENTER to close this window") {
				t.Fatalf("no prompt: %q", out.String())
			}
		})
	}
}

// The wait must be unreachable for anything that is not a person looking at a
// window. Opting out is checked here; the remaining conditions are the
// console ones, and ownsConsole is false on every platform but Windows.
func TestLauncherWindowPauseIsOptOutAndNeverAutomated(t *testing.T) {
	t.Setenv(PauseDisabledEnv, "")
	if shouldPauseForLauncherWindow(true) {
		t.Fatal("-no-pause ignored")
	}
	t.Setenv(PauseDisabledEnv, "1")
	if shouldPauseForLauncherWindow(false) {
		t.Fatalf("%s ignored", PauseDisabledEnv)
	}
	t.Setenv(PauseDisabledEnv, "")
	// A pipe is what every redirected and automated run hands the process.
	// Nothing about it is a console, so it must not qualify even if the
	// console-ownership check were somehow satisfied.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isConsoleDevice(r) || isConsoleDevice(w) {
		t.Fatal("a pipe reported as a console")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isConsoleDevice(f) {
		t.Fatal("a redirected file reported as a console")
	}
	if shouldPauseForLauncherWindow(false) && !ownsConsole() {
		t.Fatal("paused without owning a console")
	}
}
