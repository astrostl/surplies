# surplies

[![Go Report Card](https://goreportcard.com/badge/github.com/astrostl/surplies)](https://goreportcard.com/report/github.com/astrostl/surplies)

> **Disclaimer:** This tool is vibe coded and provided as-is, without warranty or guarantee of any kind. It may produce false positives, miss indicators, or behave unexpectedly. Use it as one signal among many, not as a definitive security verdict. Testing primarily performed on macOS — some Windows/WSL, no Linux.

A cross-platform CLI tool that scans key parts of your system for evidence of supply chain attacks via compromised dependencies. Pure Go, no third-party Go modules. Git-history checks require Git.

## Install

**Homebrew (macOS):**

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
brew trust --formula astrostl/surplies/surplies
brew install surplies
```

**Prebuilt binaries:** download from the [latest release](https://github.com/astrostl/surplies/releases/tag/v0.16.0) — macOS tarballs, and Linux and Windows binaries for amd64 and arm64.

**Go:**

```sh
go install github.com/astrostl/surplies@latest
```

**Build from source:**

```sh
make build       # local binary
make all         # all platforms: darwin/linux/windows x amd64/arm64
```

## What it detects

**Currently detects indicators from seven documented major supply chain attacks**, sourced from incident writeups by [StepSecurity](https://www.stepsecurity.io/), [Socket](https://socket.dev/), [OpenSourceMalware](https://opensourcemalware.com/), [Aikido](https://www.aikido.dev/), [Endor Labs](https://www.endorlabs.com/), [SafeDep](https://safedep.io/), [Snyk](https://snyk.io/), and the [TanStack](https://tanstack.com/) team, plus registry advisory data from [OSV](https://osv.dev/) and the community [NullReceiver IR kit](https://github.com/OsamaCodes62/nullreceiver-ir-kit) and [ByteGuard](https://github.com/n0m4dz/ByteGuard) (see [Attribution](docs/ATTRIBUTION.md)). The [active hash list](docs/ATTACKS.md#active-payload-hashes) also includes incident-sourced samples within the existing PolinRider campaign; those exact hashes are not published by a vendor:

- **[GlassWorm Unicode concealment](docs/ATTACKS.md#glassworm-unicode-concealment)** — invisible variation-selector payloads hidden in source, reported as contextual warnings rather than attribution
- **[axios npm compromise](docs/ATTACKS.md#axios-npm-compromise)** — `axios@1.14.1` and `0.30.4` shipped a phantom dependency that deployed a cross-platform RAT
- **[litellm PyPI compromise](docs/ATTACKS.md#litellm-pypi-compromise)** — `litellm@1.82.7` and `1.82.8` harvested credentials and installed a persistent C2 backdoor
- **[TrapDoor crypto-stealer campaign](docs/ATTACKS.md#trapdoor-crypto-stealer-campaign)** — 34 purpose-built phantom packages across npm, PyPI, and Crates.io impersonating crypto / DeFi / AI developer tooling
- **[Mini Shai-Hulud campaign](docs/ATTACKS.md#mini-shai-hulud-campaign)** — a self-spreading credential-theft worm across npm, PyPI, and Composer, in four waves totaling 400+ packages
- **[keyv npm compromise](docs/ATTACKS.md#keyv-npm-compromise)** — 11 malicious releases under one maintainer, with a preinstall loader and injected Claude Code / VS Code hooks
- **[PolinRider campaign](docs/ATTACKS.md#polinrider-campaign)** — a DPRK worm that spreads through developer machines: padded config appends, fake web fonts, `folderOpen` tasks, patched npm and editors

Every campaign, with the full technical detail, is in [Attacks covered](docs/ATTACKS.md).

## Usage

```
surplies              # scan with verbose output (default)
surplies -broad        # include unrelated text/data (slow)
surplies -browser-cache # include browser cache contents (slow)
surplies -npm-cache    # include raw npm cache contents (slow)
surplies -resolve      # also resolve known C2 domains and match their current addresses
surplies -q           # quiet mode (suppress scan details)
surplies -json        # JSON output (findings array to stdout)
surplies -version     # print version
surplies -root /custom/path  # additional full scan root; repeatable
surplies -root /custom/path -only  # scan ONLY that root; skip home and machine-wide checks
surplies -skip-tmproots # do not walk all temp directories (staging names still checked)
surplies -no-pause    # never wait for ENTER before exiting (Windows only, SURPLIES_NO_PAUSE equivalent; see below)
```

A default scan walks your home directory and your own temp directories —
`$TMPDIR` (`/var/folders/<xx>/<hash>/T` on macOS), `/tmp`, `/var/tmp`, and the
platform equivalents — recursively, the same way. The run header lists every
directory it walks. Other users' temp directories require root and are not read.

`-skip-tmproots` drops those directories from the walk, for a machine where
build and installer debris dominates the report. It narrows traversal rather
than putting temp out of scope: the documented staging filenames are still
checked at the top of each temp directory, a temp directory named with `-root` is still walked in full, and the
run prints a scope notice saying what it stopped looking for.

`-only` confines the scan to the `-root` paths given. Every check is filtered
by that scope rather than switched off wholesale: the only thing genuinely
skipped is the live-connection snapshot, which describes the machine and has no
path to confine. Every fixed path — artifacts, persistence roots, the npm CLI,
startup files, system Python paths, temp dirs — is read only where it falls
inside a requested root. Since `-only` puts the first `-root` in home's place,
the home-relative half of those checks resolves inside the tree you named, so
pointing it at an extracted home backup still reports LaunchAgents, startup
files and dropped artifacts found there. It refuses without `-root` rather than
falling back to home, and both the run header and the phase lines say what ran
and what was skipped. It is for one-off checks of a single tree, not for
concluding a machine is clean: a `-only` run that finds nothing says nothing
about the rest of the machine.

`-resolve` is off by default: looking those domains up queries nameservers the
campaign may still control, and a dead C2 domain reparked on shared hosting
resolves to an address the machine legitimately talks to. Every run says which
half of the indicator list its connection snapshot was compared against.

`-broad`, `-browser-cache`, and `-npm-cache` are independent opt-ins. Broad content scanning leaves both cache exclusions intact; each cache flag expands inspection only within its cache.

On Windows, double-clicking `surplies.exe` in Explorer gives it a console of
its own, and that window is destroyed the instant the scan exits — the report
is printed and then disappears unread. Such a run waits for ENTER before
exiting. Nothing else does: the wait is entered only when this process is the
only one attached to its console, which is true of a double-click and false of
a run from `cmd.exe`, PowerShell, a scheduled task or a service, and only when
stdin and stdout are both still that console, so anything redirected or piped
(including `-json`) is unaffected. It also gives up after a minute rather than
waiting forever. macOS and Linux never pause: their terminals already survive
the process. Use `-no-pause` or set `SURPLIES_NO_PAUSE` to switch it off.

### Scheduled scans

```sh
surplies schedule                # install daily scans at 09:00 local time
surplies schedule -time 14:30    # install or update the daily run time
surplies schedule -root ~/development -only  # scan only this directory
surplies schedule disable        # stop scheduled scans; keep installed files
surplies schedule remove         # stop and remove the schedule and helper
```

Installs a daily scan using launchd on macOS or a systemd user timer on Linux, along with the notification helper, for the current user. Run it from your normal account without `sudo`, using an installed binary you intend to keep. Rerunning updates the same schedule rather than adding another. The helper records the executable's absolute path, so it does not depend on your interactive shell's `PATH`. Windows is not supported.

Scheduled scans use the default options plus `-q`. Repeatable `-root` adds scan directories; `-only` confines inspection to those roots and requires at least one. For example, `surplies schedule -root ~/development -root ~/work -only` scans both trees. A clean scoped scan applies only to those directories. Relative paths are resolved when installed, and all roots must be existing directories. A clean scan is silent. Warning-level findings, incomplete coverage, or scan errors raise a warning notification; only a critical result (exit code 2) uses the critical title, which covers a critical finding, a scan whose Git coverage failed outright, and a scan that stopped reading because files kept timing out. The notification provides a command to inspect the same scope with details. Linux additionally requires a running systemd user manager, `notify-send` (libnotify), and a desktop notification session; the prerequisites are checked before anything is written.

`disable` also stops a scan that is running at the time, and the setting survives logout and reboot. Run `surplies schedule` again to re-enable at 09:00, or pass `-time`. Each installation replaces all settings; repeat your `-root` and `-only` options to retain a custom scope. `remove` keeps the `surplies` binary and existing scan logs.

See [scheduling details](scripts/README.md) for the exact files installed and the manual alternatives. If you previously configured cron by hand, remove that entry yourself to avoid duplicate scans.

## How it works

A scan runs six phases in sequence:

1. **Known malicious artifacts** — fixed filesystem paths, the global npm CLI, documented Electron application entrypoints and their sidecars, and persistence roots under home and system locations
2. **Project directories** — walk home, each `-root` and the temp directories, inspecting every `node_modules`, Composer `vendor/`, `.claude/` and `.vscode/`, and every build config, web font, and `.gitignore` encountered
3. **Python site-packages** — discovered environments plus well-known system Python paths
4. **Running processes** — command lines of running processes against the payload indicators already on file
5. **Network IOCs** — established connections from `netstat -n` against known C2 IPs; `-resolve` adds the current addresses behind known C2 domains
6. **Git history** — blobs reachable from local refs, matched against the [active payload hashes](docs/ATTACKS.md#active-payload-hashes) regardless of filename, plus the filename-gated checks against blobs whose committed name the project walk would have opened. This reaches a repository cleaned in the working tree whose history was never rewritten

A human-mode run ends with one verdict, coverage status, elapsed time, and content-read totals. Repeated diagnostics print their explanation once with the affected paths underneath, and expected scope limits are reported as context rather than as failures. Every run also saves all findings, exact paths, and statistics to a private `surplies-report-*.json` in the system temporary directory and prints its path, so nothing needs a second scan to retrieve. `-json` puts the complete findings array on stdout:

```sh
surplies -json | jq '.[] | select(.severity == "CRITICAL")'
```

Which files a scan actually reads — and which it deliberately does not — is documented in [Scanning behavior](docs/SCANNING.md).

## Design principles

- **Filesystem-first detection.** Never shells out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any package manager/runtime tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scans files on disk instead. The exceptions are `netstat` for live network connection IOC matching, the running-process list read through the operating system's own process interfaces (no command is run for it), and Git history scans using read-only Git plumbing on local repositories. Git scans never fetch, check out files, or run repository code/hooks/filters. A scan runs nothing else; the complete inventory, including the scheduler commands the explicitly invoked [`schedule`](#scheduled-scans) subcommand uses, is in [External commands](docs/SCANNING.md#external-commands).
- **Report only, never remediate.** Scans are read-only. A scan never deletes files, uninstalls packages, modifies configs, or takes any corrective action against a finding. Findings are reported; the user decides what to do. A scan writes only its own report file (and, with `-debug`, a debug log) in the system temporary directory. The one command that writes anything else is the explicitly invoked [`schedule`](#scheduled-scans) subcommand, which manages only its own scheduling files under the current user's account.
- **No container/orchestrator checks.** Does not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem.
- **Cross-platform.** All checks work on macOS, Linux, and Windows (amd64 and arm64). Two things outside detection are deliberately platform-specific: [`schedule`](#scheduled-scans) supports macOS and Linux only, and the [ENTER wait](#usage) for a double-clicked window is Windows-only, because only Windows destroys the window on exit.
- **Zero Go dependencies.** stdlib only. No third-party Go modules. Git history inspection requires Git 2.45 or newer, resolved from `PATH` only; an older Git cannot inspect a single repository and is reported as a critical [`git-too-old`](docs/CHECKS.md#26-git-too-old-critical) finding rather than silently skipped. Reading the names blobs were committed under requires Git 2.50; from 2.45 to 2.49 the size-matched half of the history scan runs alone, reported as a critical [`git-too-old-for-filenames`](docs/CHECKS.md#27-git-too-old-for-filenames-critical).

## Checks

| Check | Severity | What it catches |
|---|---|---|
| [`known-artifact`](docs/CHECKS.md#1-known-artifact-critical) | CRITICAL | Payloads dropped at fixed paths: RAT binaries, launchers, C2 backdoors, persistence units |
| [`phantom-dependency`](docs/CHECKS.md#2-phantom-dependency-critical) | CRITICAL | npm packages that exist only as malware delivery vehicles |
| [`compromised-version`](docs/CHECKS.md#3-compromised-version-critical) | CRITICAL | Installed npm packages matching a known-compromised version |
| [`suspicious-install-script`](docs/CHECKS.md#4-suspicious-install-script-warn) | WARN | Lifecycle scripts with download, shell-execution, or encoding patterns |
| [`obfuscated-install-script`](docs/CHECKS.md#5-obfuscated-install-script-warn) | WARN | JavaScript invoked by a lifecycle script showing obfuscation signals |
| [`npm-payload-file`](docs/CHECKS.md#6-npm-payload-file-critical) | CRITICAL | Known payload filenames inside packages of an affected scope |
| [`compromised-python-version`](docs/CHECKS.md#7-compromised-python-version-critical) | CRITICAL | Installed Python distributions matching a known-compromised version |
| [`malicious-pth-file`](docs/CHECKS.md#8-malicious-pth-file-critical) | CRITICAL | Known malicious `.pth` files, which run on every interpreter start |
| [`suspicious-pth-file`](docs/CHECKS.md#9-suspicious-pth-file-warn) | WARN | Unknown `.pth` files matching two or more malware-associated patterns |
| [`compromised-composer-version`](docs/CHECKS.md#10-compromised-composer-version-critical) | CRITICAL | Installed Composer packages matching a known-compromised version |
| [`network-ioc-active-connection`](docs/CHECKS.md#11-network-ioc-active-connection-critical) | CRITICAL | Established connections to documented C2 domains and IPs |
| [`suspicious-temp-file`](docs/CHECKS.md#12-suspicious-temp-file-warn) | WARN | Payload staging artifacts in temp directories |
| [`project-artifact`](docs/CHECKS.md#13-project-artifact-critical) | CRITICAL | Payload files dropped into a project's `.claude/` or `.vscode/` |
| [`phantom-python-package`](docs/CHECKS.md#14-phantom-python-package-critical) | CRITICAL | PyPI distributions that exist only as malware delivery vehicles |
| [`fake-font-payload`](docs/CHECKS.md#15-fake-font-payload-critical) | CRITICAL | A file named like a web font whose bytes are text, not a font container |
| [`payload-signature`](docs/CHECKS.md#16-payload-signature-critical) | CRITICAL | Published loader constants, injection markers, C2 wallet and fetch paths |
| [`padded-source-file`](docs/CHECKS.md#17-padded-source-file-warn) | WARN | 200+ consecutive spaces pushing an append off the right edge of the editor |
| [`malicious-repo-artifact`](docs/CHECKS.md#18-malicious-repo-artifact-critical) | CRITICAL | Known artifact filenames anywhere in the walk, plus any file matching a sized payload hash |
| [`gitignore-injection`](docs/CHECKS.md#19-gitignore-injection-critical) | CRITICAL | `.gitignore` entries added to hide a dropped file from `git status` |
| [`patched-npm-cli`](docs/CHECKS.md#20-patched-npm-cli-critical) | CRITICAL | An overwritten global `npm/lib/cli.js`, or a stub loading a sidecar |
| [`scan-incomplete`](docs/CHECKS.md#21-scan-incomplete-warn) | WARN | Reads, traversals, or collections that failed — coverage is not complete |
| [`patched-application`](docs/CHECKS.md#22-patched-application-critical) | CRITICAL | Patched VS Code, Cursor, Antigravity, GitHub Desktop, or Discord entrypoints |
| [`font-execution-task`](docs/CHECKS.md#23-font-execution-task-critical) | CRITICAL | A `.vscode/tasks.json` `folderOpen` task that runs a font file with Node |
| [`runtime-staging-artifact`](docs/CHECKS.md#24-runtime-staging-artifact-warn) | WARN | Documented staging paths that also have legitimate explanations |
| [`git-payload-hash`](docs/CHECKS.md#25-git-payload-hash-critical) | CRITICAL | A blob in local Git history matching an active payload hash, or carrying a documented indicator under a name the walk would have read |
| [`git-too-old`](docs/CHECKS.md#26-git-too-old-critical) | CRITICAL | An installed Git older than 2.45, which cannot inspect a single repository |
| [`git-too-old-for-filenames`](docs/CHECKS.md#27-git-too-old-for-filenames-critical) | CRITICAL | An installed Git from 2.45 to 2.49, which inspects history by size but cannot read the names blobs were committed under |
| [`scan-limited`](docs/CHECKS.md#28-scan-limited-info) | INFO | Expected scope limits, such as shallow Git history |
| [`suspicious-source-execution`](docs/CHECKS.md#29-suspicious-source-execution-warn) | WARN | Decode-and-execute, download-to-shell, or hidden detached spawn structure |
| [`unicode-concealment`](docs/CHECKS.md#30-unicode-concealment-warn) | WARN | Invisible Unicode hiding code from the reader: bidi controls, variation selectors, joiners |
| [`loader-structure`](docs/CHECKS.md#31-loader-structure-warn) | WARN | An `import.meta.url` expression immediately invoking a local `.cjs` sidecar |
| [`loader-variant`](docs/CHECKS.md#32-loader-variant-warn) | WARN | A published global injection assignment, across quoting and spacing variants |
| [`correlated-loader-markers`](docs/CHECKS.md#33-correlated-loader-markers-warn) | WARN | A community build marker alongside loader or decode/execute structure |
| [`escaped-execution`](docs/CHECKS.md#34-escaped-execution-warn) | WARN | A long run of ASCII escapes alongside dynamic execution or loader structure |
| [`asset-format-mismatch`](docs/CHECKS.md#35-asset-format-mismatch-warn) | WARN | A binary-named asset whose header is not the format it claims, or is text |
| [`disguised-file-execution-task`](docs/CHECKS.md#36-disguised-file-execution-task-warn) | WARN | An editor task running an interpreter on a binary-named file |
| [`workspace-setting-context`](docs/CHECKS.md#37-workspace-setting-context-warn-or-info) | WARN/INFO | Workspace preferences that ease automatic execution, reported as context |
| [`startup-content`](docs/CHECKS.md#38-startup-content-warn) | WARN | Startup and persistence files referencing documented staging paths or C2 addresses |
| [`hosts-c2-entry`](docs/CHECKS.md#39-hosts-c2-entry-warn) | WARN | A hosts file entry mapping a name to a known C2 IP |
| [`missing-script-target`](docs/CHECKS.md#40-missing-script-target-info) | INFO | A lifecycle script naming a file that is not installed |
| [`running-payload-process`](docs/CHECKS.md#41-running-payload-process-critical) | CRITICAL | A running process executing a fake font, naming an injection sidecar, or running a known payload |

What each one looks for, how it decides, and why it exists: [Checks](docs/CHECKS.md).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan, no indicators found |
| 1 | Warning-level findings only, including a Git scan that found no repositories at all |
| 2 | At least one critical finding; a Git older than 2.50 with repositories to scan; unusable Git coverage: more than 25% of the Git repositories found could not be scanned (including any run that scanned none of them); or a scan that stopped reading after one minute of timed-out reads |

## Documentation

- [Attacks covered](docs/ATTACKS.md) — every campaign in detail, and the active payload hash list
- [Checks](docs/CHECKS.md) — all 41 checks, their tables, and their reasoning
- [Scanning behavior](docs/SCANNING.md) — design principles, what gets read, scope decisions, and performance diagnostics
- [Attribution](docs/ATTRIBUTION.md) — the researchers and writeups every indicator comes from
- [Scheduling details](scripts/README.md) — the exact files `surplies schedule` installs
- [Release process](RELEASE.md)

## License

MIT
