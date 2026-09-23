package scan

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Command lines come from NtQueryInformationProcess(ProcessCommandLineInformation),
// available since Windows 8.1, with a query-limited handle; the working
// directory lives in another process's PEB and is not read.
const (
	processQueryLimitedInformation = 0x1000
	processCommandLineInformation  = 60
	statusInfoLengthMismatch       = 0xC0000004
	statusAccessDenied             = 0xC0000022
)

var procNtQueryInformationProcess = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess")

func listProcesses() (processSnapshot, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return processSnapshot{}, err
	}
	defer syscall.CloseHandle(snapshot)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return processSnapshot{}, err
	}
	var snap processSnapshot
	for {
		// PID 0 is the idle process and 4 is System; neither has a command line.
		if pid := entry.ProcessID; pid > 4 {
			args, err := windowsCommandLine(pid)
			switch {
			case err == nil:
				exe := syscall.UTF16ToString(entry.ExeFile[:])
				snap.procs = append(snap.procs, processInfo{PID: int(pid), Exe: exe, Args: args})
			case errors.Is(err, syscall.ERROR_ACCESS_DENIED):
				snap.restricted++
			}
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				return snap, nil
			}
			return snap, err
		}
	}
}

func windowsCommandLine(pid uint32) ([]string, error) {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)
	size := uint32(4096)
	var buf []byte
	queried := false
	for range 3 {
		buf = make([]byte, size)
		status, _, _ := procNtQueryInformationProcess.Call(uintptr(h), processCommandLineInformation,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size)))
		if status == statusInfoLengthMismatch {
			continue
		}
		if status == statusAccessDenied {
			return nil, syscall.ERROR_ACCESS_DENIED
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%08X", status)
		}
		queried = true
		break
	}
	if !queried {
		return nil, fmt.Errorf("NtQueryInformationProcess: command line kept growing")
	}
	// A UNICODE_STRING header followed by the text it points at.
	type unicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	}
	us := (*unicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return nil, nil
	}
	text := unsafe.Slice(us.Buffer, us.Length/2)
	line := make([]uint16, len(text)+1)
	copy(line, text)
	var argc int32
	argv, err := syscall.CommandLineToArgv(&line[0], &argc)
	if err != nil {
		return nil, err
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(argv))))
	args := make([]string, argc)
	for i := range args {
		args[i] = syscall.UTF16ToString((*argv[i])[:])
	}
	return args, nil
}
