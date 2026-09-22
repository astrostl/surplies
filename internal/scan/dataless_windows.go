package scan

import (
	"io/fs"
	"syscall"
)

// Windows marks placeholders with reparse-point attributes rather than one
// flag. OFFLINE is the legacy HSM marker; the two RECALL attributes are what
// the Cloud Files API sets, and Microsoft documents them as the signal an
// antivirus or indexer must honour so it does not fault the whole drive down
// from the provider. Any of the three means the bytes are not local.
const (
	fileAttributeOffline            = 0x00001000
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000
	fileAttributeNotLocal           = fileAttributeOffline | fileAttributeRecallOnOpen | fileAttributeRecallOnDataAccess
)

func datalessFile(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&fileAttributeNotLocal != 0
}

func materializationRefused(error) bool { return false }
