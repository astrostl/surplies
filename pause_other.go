//go:build !windows

package main

// Only Windows destroys the window when the process exits. macOS Terminal
// leaves a double-clicked binary's window open with "[Process completed]",
// and Linux file managers do not hand a binary a terminal to begin with.
// There is also nothing to detect with: the Unix equivalent would mean
// inspecting the parent process to guess at Finder, which is both unreliable
// and the kind of process inspection this scanner stays out of.
func ownsConsole() bool { return false }
