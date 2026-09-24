# surplies scripts

Helper scripts for integrating `surplies` into your system's scheduled tasks and notification pipeline.

## Automatic setup

Use an installed `surplies` binary from your normal user account:

```sh
surplies schedule                 # daily at 09:00 local time
surplies schedule -time 18:30     # update to 6:30 PM
surplies schedule -root ~/development -root ~/work -only  # scan only these trees
```

The CLI embeds these scripts; no repository checkout or manual copy is needed.
It writes `~/.local/bin/surplies-notify` with the executable's absolute path,
then installs and activates the platform schedule. Existing files with the same
names are replaced. Other schedules are left alone.

`-root` is repeatable and adds directories to the default scan. Add `-only` to
confine inspection to the selected roots; it requires at least one `-root`.
Relative paths are made absolute at installation, and each root must be an
existing directory. Paths with spaces or shell characters are safely quoted.
A clean scoped scan applies only to the selected directories. Failures inspecting
those directories still notify; expected scope exclusions remain informational.

Every installation replaces the previous time and scope. Omitted settings revert
to 09:00 and the default full scope. Repeat all desired flags when updating or
re-enabling a schedule. Installation output and notifications include a command
that runs the same scope with details.

- **macOS:** `~/Library/LaunchAgents/com.surplies.notify.plist`, with output in
  `~/Library/Logs/surplies-notify.log`. Requires a logged-in GUI session.
- **Linux:** `surplies-notify.service` and `surplies-notify.timer` in
  `$XDG_CONFIG_HOME/systemd/user` (default `~/.config/systemd/user`). Requires
  systemd's user manager and `notify-send`. The persistent timer catches up a
  missed run when the user manager starts; desktop notifications require a
  desktop session and its notification service.

Run the command again after moving the binary. Remove any previously configured
cron entry yourself to avoid duplicate scans. Windows scheduling is not supported.

To disable or remove the installed schedule:

```sh
surplies schedule disable  # stop scheduled scans, including a running scan; keep files
surplies schedule remove   # stop scans and delete the schedule files and helper
```

Disabling persists across login/reboot. Run `surplies schedule` to enable daily
scans at 09:00 again, or provide `-time HH:MM`. Removal keeps the CLI binary,
existing logs, and unrelated files. Manually configured cron entries must still
be removed separately.

## notify/

Scripts that run `surplies` and send a desktop notification when a scan exits nonzero. Warning-level findings, incomplete coverage, and scan errors use neutral warning text; exit code 2 uses the critical message, which covers a critical finding, a scan whose Git coverage failed outright, and a scan that stopped reading because files kept timing out. Clean scans are silent.

Notification behavior follows `surplies`' exit codes:

| Exit code | Meaning | Notification title |
|-----------|---------|-------------------|
| `0` | Clean — no indicators found | *(none)* |
| `1` | Warning-level findings, or incomplete coverage | `Surplies: Warning` |
| `2` | Critical finding, unusable Git coverage, or reading stopped after repeated timeouts | `Surplies: Critical` |
| anything else | The scan errored or did not run | `Surplies: Warning` |

Only `2` is an attack indicator. Every other nonzero code shares the neutral
warning wording, because a coverage gap and a failed run are not findings and
must never be announced as one.

### macOS (`notify/macos.sh`)

Uses `osascript` (built-in, no extra dependencies).

**Manual setup with launchd (runs daily at 9 AM):**

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

**Manual setup with cron (runs daily at 9 AM):**

```sh
cp scripts/notify/linux.sh ~/.local/bin/surplies-notify
chmod +x ~/.local/bin/surplies-notify
# Add to crontab:
(crontab -l 2>/dev/null; echo "0 9 * * * DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus ~/.local/bin/surplies-notify") | crontab -
```

**Manual setup with a systemd timer:**

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
3. Fire the platform's native critical notification for code `2`; use neutral warning text for other nonzero codes

Use `#!/bin/sh` for shell scripts where possible (POSIX-portable). No JSON parsing needed — the exit code is the reliable interface.
