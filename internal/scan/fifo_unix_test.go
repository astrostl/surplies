//go:build !windows

package scan

import "syscall"

func mkfifo(path string) error { return syscall.Mkfifo(path, 0644) }
