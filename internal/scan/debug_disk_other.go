//go:build !darwin

package scan

func selfDiskIO() DebugDiskIO {
	return DebugDiskIO{Error: "disk byte counters are currently implemented on macOS only"}
}
func childDiskIO(pid int) DebugDiskIO { return selfDiskIO() }
