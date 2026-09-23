package scan

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"unsafe"
)

// proc_info(2) and sysctl(3) through the libc syscall entry the standard
// library already uses; the constants are from <sys/proc_info.h> and
// <sys/sysctl.h>.
const (
	procInfoCallListPIDs = 1
	procInfoCallPIDInfo  = 2
	procAllPIDs          = 1
	procPIDVnodePathInfo = 9
	vnodeInfoSize        = 152
	vnodePathInfoSize    = 2 * (vnodeInfoSize + 1024)
	ctlKern              = 1
	kernProc             = 14
	kernProcPID          = 1
	kernProcArgs2        = 49
	// struct kinfo_proc is 648 bytes on 64-bit macOS, with
	// kp_eproc.e_ucred.cr_uid at offset 420.
	kinfoProcSize = 648
	kinfoProcUID  = 420
)

func listProcesses() (processSnapshot, error) {
	pids, err := darwinPIDs()
	if err != nil {
		return processSnapshot{}, err
	}
	var snap processSnapshot
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		exe, args, err := darwinProcArgs(pid)
		if err != nil {
			// The kernel answers EINVAL both for another user's process and
			// for one that exited or is a zombie; only the first is a gap.
			if uid, ok := darwinProcUID(pid); ok && uid != uint32(syscall.Getuid()) {
				snap.restricted++
			}
			continue
		}
		snap.procs = append(snap.procs, processInfo{PID: int(pid), Exe: exe, Args: args, Cwd: darwinCwd(pid)})
	}
	return snap, nil
}

func darwinPIDs() ([]int32, error) {
	n, _, e := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallListPIDs, procAllPIDs, 0, 0, 0, 0)
	if e != 0 {
		return nil, e
	}
	// Room for processes started between the two calls.
	buf := make([]int32, n/4+256)
	n, _, e = syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallListPIDs, procAllPIDs, 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*4))
	if e != 0 {
		return nil, e
	}
	return buf[:min(int(n/4), len(buf))], nil
}

func darwinSysctl(mib []int32) ([]byte, error) {
	size := uintptr(0)
	if _, _, e := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)), 0, uintptr(unsafe.Pointer(&size)), 0, 0); e != 0 {
		return nil, e
	}
	if size == 0 {
		return nil, syscall.EINVAL
	}
	buf := make([]byte, size)
	if _, _, e := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, 0); e != 0 {
		return nil, e
	}
	return buf[:size], nil
}

func darwinProcUID(pid int32) (uint32, bool) {
	buf, err := darwinSysctl([]int32{ctlKern, kernProc, kernProcPID, pid})
	if err != nil || len(buf) != kinfoProcSize {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf[kinfoProcUID:]), true
}

// KERN_PROCARGS2 is argc, the executable path, NUL padding, then argv.
func darwinProcArgs(pid int32) (string, []string, error) {
	buf, err := darwinSysctl([]int32{ctlKern, kernProcArgs2, pid})
	if err != nil {
		return "", nil, err
	}
	return parseProcArgs2(buf)
}

func parseProcArgs2(buf []byte) (string, []string, error) {
	if len(buf) < 4 {
		return "", nil, syscall.EINVAL
	}
	argc := int(binary.LittleEndian.Uint32(buf))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", nil, syscall.EINVAL
	}
	exe := string(rest[:i])
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	args := make([]string, 0, argc)
	for len(args) < argc && len(rest) > 0 {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			j = len(rest)
		}
		args = append(args, string(rest[:j]))
		rest = rest[min(j+1, len(rest)):]
	}
	return exe, args, nil
}

// struct proc_vnodepathinfo: the cwd's vnode_info, then its path.
func darwinCwd(pid int32) string {
	buf := make([]byte, vnodePathInfoSize)
	n, _, e := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), procPIDVnodePathInfo, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 || int(n) != len(buf) {
		return ""
	}
	path := buf[vnodeInfoSize : vnodeInfoSize+1024]
	if i := bytes.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}
	return string(path)
}
