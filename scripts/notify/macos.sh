#!/bin/sh
# Send a macOS notification when surplies reports a warning or critical result.
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
