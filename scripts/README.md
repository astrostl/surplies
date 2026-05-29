# surplies scripts

Helper scripts for integrating `surplies` into your system's scheduled tasks and notification pipeline.

## notify/

Scripts that run `surplies` and send a desktop notification **only when findings are detected**. Silent on clean scans — no noise, no false positives.

Severity maps to notification urgency using `surplies`' exit codes:

| Exit code | Meaning | Notification title |
|-----------|---------|-------------------|
| `0` | Clean — no indicators found | *(none)* |
| `1` | Warning-level findings | `Surplies: Warning` |
| `2` | Critical finding | `Surplies: Critical Finding` |

### macOS (`notify/macos.sh`)

Uses `osascript` (built-in, no extra dependencies).

**Setup with launchd (runs daily at 9 AM):**

1. Copy the script and make it executable:
   ```sh
   cp scripts/notify/macos.sh ~/.local/bin/surplies-notify
   chmod +x ~/.local/bin/surplies-notify
   ```

2. Create `~/Library/LaunchAgents/com.surplies.notify.plist`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.surplies.notify</string>
       <key>ProgramArguments</key>
       <array>
           <string>/bin/sh</string>
           <string>/Users/YOUR_USERNAME/.local/bin/surplies-notify</string>
       </array>
       <key>StartCalendarInterval</key>
       <dict>
           <key>Hour</key>
           <integer>9</integer>
           <key>Minute</key>
           <integer>0</integer>
       </dict>
       <key>StandardOutPath</key>
       <string>/Users/YOUR_USERNAME/Library/Logs/surplies-notify.log</string>
       <key>StandardErrorPath</key>
       <string>/Users/YOUR_USERNAME/Library/Logs/surplies-notify.log</string>
   </dict>
   </plist>
   ```

3. Load it:
   ```sh
   launchctl load ~/Library/LaunchAgents/com.surplies.notify.plist
   ```

### Linux (`notify/linux.sh`)

Uses `notify-send` from [libnotify](https://gitlab.gnome.org/GNOME/libnotify). Available on most desktop distributions (`apt install libnotify-bin` / `dnf install libnotify`).

**Setup with cron (runs daily at 9 AM):**

```sh
cp scripts/notify/linux.sh ~/.local/bin/surplies-notify
chmod +x ~/.local/bin/surplies-notify
# Add to crontab:
(crontab -l 2>/dev/null; echo "0 9 * * * DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus ~/.local/bin/surplies-notify") | crontab -
```

**Setup with a systemd timer:**

`~/.config/systemd/user/surplies-notify.service`:
```ini
[Unit]
Description=surplies supply chain scan

[Service]
ExecStart=%h/.local/bin/surplies-notify
```

`~/.config/systemd/user/surplies-notify.timer`:
```ini
[Unit]
Description=Run surplies daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
systemctl --user enable --now surplies-notify.timer
```

### Windows

Contributions welcome. The same exit-code contract applies (`0` = clean, `1` = warning, `2` = critical). A PowerShell script using `New-BurntToastNotification` or the native `[Windows.UI.Notifications.ToastNotificationManager]` API would fit here as `notify/windows.ps1`.

## Adding a new platform

Each notify script should:

1. Run `surplies -q >/dev/null 2>&1` and capture the exit code
2. Exit silently if the code is `0`
3. Fire the platform's native notification mechanism with an appropriate urgency/title based on whether the code is `1` (warning) or `2` (critical)

Use `#!/bin/sh` for shell scripts where possible (POSIX-portable). No JSON parsing needed — the exit code is the reliable interface.
