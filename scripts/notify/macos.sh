#!/bin/sh
# Send a macOS notification for findings or incomplete scan coverage.
# Silent on clean scans. Intended for use with launchd or cron.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -eq 0 ] && exit 0

if [ "$code" -eq 2 ]; then
    osascript -e "display notification \"Critical supply chain attack indicators, or a scan whose coverage failed. Run 'surplies' for details.\" with title \"Surplies: Critical\" sound name \"Basso\""
else
    osascript -e "display notification \"The scan found warnings, incomplete coverage, or an error. Run 'surplies' for details.\" with title \"Surplies: Warning\""
fi

details_command=surplies
osascript -e 'on run argv' \
    -e 'display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"' \
    -e 'end run' "$title" "Scan findings or incomplete coverage require review. Run for details: $details_command"
