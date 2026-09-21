#!/bin/sh
# Send a desktop notification when surplies reports a warning or critical result.
# Requires libnotify (notify-send). Silent on clean scans.
# Intended for use with cron or a systemd timer.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -eq 0 ] && exit 0

if [ "$code" -eq 2 ]; then
    notify-send -u critical "Surplies: Critical" "Critical supply chain attack indicators, or a scan whose coverage failed. Run 'surplies' for details."
else
    notify-send -u normal "Surplies: Warning" "The scan found warnings, incomplete coverage, or an error. Run 'surplies' for details."
fi
