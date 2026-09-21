package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"
)

// A double-clicked surplies.exe gets a console of its own, and conhost
// destroys that window the moment the process exits: the scan runs, prints
// everything it found, and vanishes. Waiting for ENTER fixes that, but a
// scanner that blocks forever on a fleet machine is worse than one whose
// window closes, so the wait is entered only when the run is unambiguously a
// human staring at a window that is about to disappear, and it is bounded
// even then. See shouldPauseForLauncherWindow for how that is decided;
// nothing outside Windows ever pauses.
const launcherWindowPauseTimeout = time.Minute

// PauseDisabledEnv turns the wait off for anything the detection gets wrong.
const PauseDisabledEnv = "SURPLIES_NO_PAUSE"

// pauseForLauncherWindow waits for ENTER, or for the timeout, whichever comes
// first. The timeout is the point: a scheduled task that somehow reaches this
// wait loses a minute, not the machine's whole scan window.
func pauseForLauncherWindow(out io.Writer, in io.Reader, timeout time.Duration) {
	fmt.Fprintf(out, "\nPress ENTER to close this window (closes automatically in %s).\n", timeout)
	entered := make(chan struct{})
	// Deliberately unsupervised: the process exits immediately after this
	// function returns, so a reader still blocked on a console nobody typed
	// into goes away with it.
	go func() {
		bufio.NewReader(in).ReadString('\n')
		close(entered)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-entered:
	case <-timer.C:
	}
}

// shouldPauseForLauncherWindow reports whether this run is a file-manager
// launch whose window is about to close. Every condition has to hold:
//
//   - the user did not opt out, by flag or by environment;
//   - this process is the only one attached to its console, which is true of
//     a double-click and false of a shell, a scheduled task and a service
//     (ownsConsole is false everywhere but Windows);
//   - stdin and stdout are both still the console, so a redirected or piped
//     run -- every automated one, including -json -- returns immediately.
func shouldPauseForLauncherWindow(noPause bool) bool {
	if noPause || os.Getenv(PauseDisabledEnv) != "" {
		return false
	}
	if !ownsConsole() {
		return false
	}
	return isConsoleDevice(os.Stdin) && isConsoleDevice(os.Stdout)
}

func isConsoleDevice(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
