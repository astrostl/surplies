//go:build !darwin && !windows

package scan

import "io/fs"

// Linux has no placeholder concept to report: the sync clients that run there
// materialize everything they present, so a file that appears in the tree has
// its bytes on disk. A read that hangs anyway is a broken mount, which the
// stall budget covers.
func datalessFile(fs.FileInfo) bool { return false }

func materializationRefused(error) bool { return false }
