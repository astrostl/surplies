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

**Prebuilt binaries:** download from the [latest release](https://github.com/astrostl/surplies/releases/tag/v0.11.4) — macOS tarballs, and Linux and Windows binaries for amd64 and arm64.

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
surplies -q           # quiet mode (suppress scan details)
surplies -json        # JSON output (findings array to stdout)
surplies -version     # print version
surplies -root /custom/path  # additional full scan root; repeatable
surplies -root /custom/path -only  # scan ONLY that root; skip home and machine-wide checks
```

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

`-broad`, `-browser-cache`, and `-npm-cache` are independent opt-ins. Broad content scanning leaves both cache exclusions intact; each cache flag expands inspection only within its cache.

### Scheduled scans

```sh
surplies schedule                # install daily scans at 09:00 local time
surplies schedule -time 14:30    # install or update the daily run time
surplies schedule disable        # stop scheduled scans; keep installed files
surplies schedule remove         # stop and remove the schedule and helper
```

Installs a daily scan using launchd on macOS or a systemd user timer on Linux, along with the notification helper, for the current user. Run it from your normal account without `sudo`, using an installed binary you intend to keep. Rerunning updates the same schedule rather than adding another. The helper records the executable's absolute path, so it does not depend on your interactive shell's `PATH`. Windows is not supported.

Scheduled scans use the default options plus `-q`. A clean scan is silent; any nonzero exit, including incomplete coverage, raises a desktop notification. Run `surplies` yourself for the details. Linux additionally requires a running systemd user manager, `notify-send` (libnotify), and a desktop notification session; the prerequisites are checked before anything is written.

`disable` also stops a scan that is running at the time, and the setting survives logout and reboot. Run `surplies schedule` again to re-enable at 09:00, or pass `-time`. `remove` keeps the `surplies` binary and existing scan logs.

See [scheduling details](scripts/README.md) for the exact files installed and the manual alternatives. If you previously configured cron by hand, remove that entry yourself to avoid duplicate scans.

## How it works

A scan runs six phases in sequence:

1. **Known malicious artifacts** — fixed filesystem paths, the global npm CLI, documented Electron application entrypoints and their sidecars, and persistence roots under home and system locations
2. **Project directories** — walk home and each `-root`, inspecting every `node_modules`, Composer `vendor/`, `.claude/` and `.vscode/`, and every build config, web font, and `.gitignore` encountered
3. **Python site-packages** — discovered environments plus well-known system Python paths
4. **Network IOCs** — established connections from `netstat -n` against known C2 IPs and on-the-fly resolutions of known C2 domains
5. **Temp directories** — payload remnants and staging artifacts
6. **Git history** — blobs reachable from local refs, matched against the [active payload hashes](docs/ATTACKS.md#active-payload-hashes) regardless of filename

A human-mode run ends with one verdict, coverage status, elapsed time, and content-read totals. Repeated diagnostics print their explanation once with the affected paths underneath, and expected scope limits are reported as context rather than as failures. Every run also saves all findings, exact paths, and statistics to a private `surplies-report-*.json` in the system temporary directory and prints its path, so nothing needs a second scan to retrieve. `-json` puts the complete findings array on stdout:

```sh
surplies -json | jq '.[] | select(.severity == "CRITICAL")'
```

Which files a scan actually reads — and which it deliberately does not — is documented in [Scanning behavior](docs/SCANNING.md).

## Design principles

- **Filesystem-first detection.** Never shells out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any package manager/runtime tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scans files on disk instead. The exceptions are `netstat` for live network connection IOC matching and Git history scans using read-only Git plumbing on local repositories. Git scans never fetch, check out files, or run repository code/hooks/filters.
- **Report only, never remediate.** Scans are read-only. A scan never deletes files, uninstalls packages, modifies configs, or takes any corrective action against a finding. Findings are reported; the user decides what to do. The one command that writes anything is the explicitly invoked [`schedule`](#scheduled-scans) subcommand, which manages only its own scheduling files under the current user's account.
- **No container/orchestrator checks.** Does not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem.
- **Cross-platform.** All checks work on macOS, Linux, and Windows (amd64 and arm64).
- **Zero Go dependencies.** stdlib only. No third-party Go modules. Git history inspection requires Git with support for `--no-lazy-fetch`.

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
| [`git-payload-hash`](docs/CHECKS.md#25-git-payload-hash-critical) | CRITICAL | A blob in local Git history matching an active payload hash |
| [`scan-limited`](docs/CHECKS.md#26-scan-limited-info) | INFO | Expected scope limits, such as shallow Git history |

What each one looks for, how it decides, and why it exists: [Checks](docs/CHECKS.md).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan, no indicators found |
| 1 | Warning-level findings only |
| 2 | At least one critical finding |

## Documentation

- [Attacks covered](docs/ATTACKS.md) — every campaign in detail, and the active payload hash list
- [Checks](docs/CHECKS.md) — all 26 checks, their tables, and their reasoning
- [Scanning behavior](docs/SCANNING.md) — design principles, what gets read, scope decisions, and performance diagnostics
- [Attribution](docs/ATTRIBUTION.md) — the researchers and writeups every indicator comes from
- [Scheduling details](scripts/README.md) — the exact files `surplies schedule` installs
- [Release process](RELEASE.md)

## License

MIT
