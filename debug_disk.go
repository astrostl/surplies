package main

import (
	"context"
	"os/exec"
)

// OS-accounted disk bytes are distinct from logical content reads and pipe bytes.
// Available distinguishes an observed zero from an unsupported/failed measurement.
type DebugDiskIO struct {
	Available             bool
	ReadBytes, WriteBytes uint64
	Error                 string `json:",omitempty"`
}

func diskIODelta(start, end DebugDiskIO) DebugDiskIO {
	if !start.Available {
		return start
	}
	if !end.Available {
		return end
	}
	if end.ReadBytes < start.ReadBytes || end.WriteBytes < start.WriteBytes {
		return DebugDiskIO{Error: "OS disk counters decreased"}
	}
	return DebugDiskIO{Available: true, ReadBytes: end.ReadBytes - start.ReadBytes, WriteBytes: end.WriteBytes - start.WriteBytes}
}
func waitDebugGit(ctx context.Context, cmd *exec.Cmd) (error, DebugDiskIO) {
	var sample DebugDiskIO
	if d, _ := ctx.Value(debugContextKey{}).(*scanDebug); d != nil && cmd.Process != nil {
		sample = childDiskIO(cmd.Process.Pid)
	}
	return cmd.Wait(), sample
}
