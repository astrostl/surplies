package main

import (
	_ "embed"

	"github.com/astrostl/surplies/internal/schedule"
)

// The notification helpers live at the repository root under scripts/ because
// they are documented for manual installation as well. An embed pattern cannot
// traverse upward, so the root package owns the directives and hands the
// contents to internal/schedule.

//go:embed scripts/notify/macos.sh
var macNotify string

//go:embed scripts/notify/linux.sh
var linuxNotify string

func notifyScripts() schedule.Scripts {
	return schedule.Scripts{Darwin: macNotify, Linux: linuxNotify}
}
