#!/bin/sh
# Send a desktop notification for findings or incomplete scan coverage.
# Requires libnotify (notify-send). Silent on clean scans.
# Intended for use with cron or a systemd timer.
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

urgency=normal
[ "$code" -eq 2 ] && urgency=critical
notify-send -u "$urgency" "$title" "$message"
