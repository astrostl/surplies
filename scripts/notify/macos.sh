#!/bin/sh
# Send a macOS notification when surplies finds supply chain attack indicators.
# Silent on clean scans. Intended for use with launchd or cron.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -eq 0 ] && exit 0

if [ "$code" -eq 2 ]; then
    title="Surplies: Critical Finding"
else
    title="Surplies: Warning"
fi

osascript -e "display notification \"Supply chain attack indicators detected. Run 'surplies' for details.\" with title \"$title\" sound name \"Basso\""
