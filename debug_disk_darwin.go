//go:build darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// Mirrors rusage_info_v2 in the macOS SDK (sys/resource.h).
// proc_pid_rusage is a thin wrapper around this proc_info syscall:
// https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
// No cgo or external executable is needed, including for cross builds.
type darwinRusageV2 struct {
	UUID                                                                       [16]byte
	UserTime, SystemTime, PkgIdleWakeups, InterruptWakeups                     uint64
	Pageins, WiredSize, ResidentSize, PhysFootprint                            uint64
	StartTime, ExitTime                                                        uint64
	ChildUserTime, ChildSystemTime, ChildPkgIdleWakeups, ChildInterruptWakeups uint64
	ChildPageins, ChildElapsedTime                                             uint64
	DiskReadBytes, DiskWriteBytes                                              uint64
}

func pidDiskIO(pid int) DebugDiskIO {
	var r darwinRusageV2
	const pidRusage = 9
	const rusageV2 = 2
	_, _, err := syscall.Syscall6(syscall.SYS_PROC_INFO, pidRusage, uintptr(pid), rusageV2, 0, uintptr(unsafe.Pointer(&r)), 0)
	if err != 0 {
		return DebugDiskIO{Error: err.Error()}
	}
	return DebugDiskIO{Available: true, ReadBytes: r.DiskReadBytes, WriteBytes: r.DiskWriteBytes}
}
func selfDiskIO() DebugDiskIO { return pidDiskIO(os.Getpid()) }

// Wait without reaping so even short-lived Git commands have a final sample.
// Cmd.Wait remains responsible for reaping, exit status, pipes and cancellation.
func childDiskIO(pid int) DebugDiskIO {
	var info [16]uint64 // siginfo_t is 104 bytes on Darwin; aligned spare space.
	const pPID, wExited, wNowait = 1, 4, 0x20
	for {
		_, _, err := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(pid), uintptr(unsafe.Pointer(&info)), wExited|wNowait, 0, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != 0 {
			return DebugDiskIO{Error: err.Error()}
		}
		return pidDiskIO(pid)
	}
}
