#!/bin/sh
# Send a macOS notification for findings or incomplete scan coverage.
# Silent on clean scans. Intended for use with launchd or cron.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -eq 0 ] && exit 0

details_command=surplies
if [ "$code" -eq 2 ]; then
    title="Surplies: Critical"
    message="Critical supply chain attack indicators, or a scan whose coverage failed."
else
    title="Surplies: Warning"
    message="The scan found warnings, incomplete coverage, or an error."
fi
message="$message Run for details: $details_command"

if [ "$code" -eq 2 ]; then
    notification='display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"'
else
    notification='display notification (item 2 of argv) with title (item 1 of argv)'
fi
osascript -e 'on run argv' -e "$notification" -e 'end run' "$title" "$message"
