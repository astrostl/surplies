#!/bin/sh
# Send a desktop notification when surplies finds supply chain attack indicators.
# Requires libnotify (notify-send). Silent on clean scans.
# Intended for use with cron or a systemd timer.
# See scripts/README.md for setup instructions.

surplies -q >/dev/null 2>&1
code=$?
[ "$code" -eq 0 ] && exit 0

if [ "$code" -eq 2 ]; then
    title="Surplies: Critical Finding"
    urgency="critical"
else
    title="Surplies: Warning"
    urgency="normal"
fi

notify-send -u "$urgency" "$title" "Supply chain attack indicators detected. Run 'surplies' for details."
