package main

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

type debugContextKey struct{}
type debugGitRead struct {
	io.Reader
	bytes atomic.Int64
}

func (r *debugGitRead) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.bytes.Add(int64(n))
	return n, e
}
func recordGit(ctx context.Context, repo string, args []string, start time.Time, stdout, stderr int64, err error, disk DebugDiskIO) {
	d, _ := ctx.Value(debugContextKey{}).(*scanDebug)
	if d == nil {
		return
	}
	c := DebugGitCommand{DiskIO: disk, Repository: repo, Args: args, Elapsed: time.Since(start), StdoutBytes: stdout, StderrBytes: stderr}
	if err != nil {
		c.Error = err.Error()
	}
	d.mu.Lock()
	d.report.GitCommands = append(d.report.GitCommands, c)
	fmt.Fprintf(d.out, "[debug] git repo=%q args=%q elapsed=%s stdout-bytes=%d stderr-bytes=%d disk-io=%+v error=%q\n", repo, args, c.Elapsed, stdout, stderr, disk, c.Error)
	d.mu.Unlock()
}
