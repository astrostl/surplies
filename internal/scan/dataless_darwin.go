package scan

import (
	"errors"
	"io/fs"
	"syscall"
)

// SF_DATALESS marks a file whose bytes are not on local disk: a cloud-sync
// placeholder that iCloud Drive, OneDrive, Dropbox or Google Drive will
// materialize on first read. The flag is set by the kernel, cleared once the
// file is hydrated, and readable from the lstat the walk already performs, so
// asking costs nothing and never triggers a download.
const sfDataless = 0x40000000

func datalessFile(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Flags&sfDataless != 0
}

// EDEADLK ("resource deadlock avoided") is what macOS returns when it will not
// materialize a dataless file or directory for this process. It is the same
// placeholder the flag above marks, reached through an open or a directory
// listing instead of a stat.
func materializationRefused(err error) bool {
	return errors.Is(err, syscall.EDEADLK)
}
