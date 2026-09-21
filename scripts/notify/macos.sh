#!/bin/sh
# Send a macOS notification when surplies finds a critical supply chain attack indicator.
# Silent unless the scan exits 2. Intended for use with launchd or cron.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -ne 2 ] && exit 0

osascript -e "display notification \"Supply chain attack indicators detected. Run 'surplies' for details.\" with title \"Surplies: Critical Finding\" sound name \"Basso\""
