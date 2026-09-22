package main

import (
	"syscall"
	"unsafe"
)

// GetConsoleProcessList returns how many processes share this console. One
// means the console was created for this process alone, which is what an
// Explorer double-click does; a run from cmd.exe or PowerShell counts the
// shell too, and a process with no console at all -- a scheduled task, a
// service -- makes the call fail and return zero.
//
// kernel32.dll is in the system KnownDLLs list, so it resolves from the
// system copy rather than the search path. Find() rather than a bare Call()
// because LazyProc.Call panics when the symbol is missing, and a scanner must
// not die on the way out.
// https://learn.microsoft.com/en-us/windows/console/getconsoleprocesslist
var getConsoleProcessList = syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleProcessList")

func ownsConsole() bool {
	if err := getConsoleProcessList.Find(); err != nil {
		return false
	}
	// Two is all the answer needed: any second process means a shell or a
	// parent is sharing the console and the window will outlive this scan.
	var pids [2]uint32
	attached, _, _ := getConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return attached == 1
}
