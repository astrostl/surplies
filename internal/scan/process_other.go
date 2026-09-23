//go:build !darwin && !linux && !windows

package scan

import (
	"fmt"
	"runtime"
)

func listProcesses() (processSnapshot, error) {
	return processSnapshot{}, fmt.Errorf("process listing is not implemented on %s", runtime.GOOS)
}
