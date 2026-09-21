#!/bin/sh
# Send a desktop notification when surplies finds a critical supply chain attack indicator.
# Requires libnotify (notify-send). Silent unless the scan exits 2.
# Intended for use with cron or a systemd timer.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -ne 2 ] && exit 0

notify-send -u critical "Surplies: Critical Finding" "Supply chain attack indicators detected. Run 'surplies' for details."
