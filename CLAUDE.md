# surplies

## Design principles

- **Filesystem-only detection.** Never shell out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any other tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scan files on disk instead. The exceptions are `netstat` for live network connection IOC matching, and default Git history scans using read-only Git plumbing to inspect locally available refs and raw objects. Git scans must never fetch (including lazy fetching), check out files, execute hooks/filters, or modify repositories. The `schedule` subcommand additionally runs `launchctl`, `systemctl --user`, and `notify-send`; this is outside detection entirely and is covered by the scheduling carve-out below.
- **Report only, never remediate.** surplies is a read-only scanner. A scan must never delete files, uninstall packages, modify configs, or take any corrective action in response to a finding. Findings are reported; the user decides what to do. See the scheduling carve-out below for the single, explicitly invoked exception.
- **No container/orchestrator checks.** Do not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem rooted at the user's home directory and explicitly added `-root` directories (plus well-known system paths for artifact checks).
- **Cross-platform.** All checks must work on macOS, Linux, and Windows (amd64 and arm64). Use `runtime.GOOS` for platform-specific paths; never assume a single OS. The `schedule` subcommand is the one deliberate exception: it supports macOS and Linux only and refuses cleanly elsewhere, because Windows has no equivalent user-level scheduler already covered by the embedded helpers.
- **Zero dependencies.** stdlib only. No third-party Go modules. Git history inspection requires an installed Git supporting `--no-lazy-fetch`.
- **Citation-required IOCs.** Only add checks for attacks that the developer explicitly requests with a linked, referenced source. Never speculatively add IOCs or checks from general knowledge.

### Scheduling subcommand

`surplies schedule` is the only code path that writes outside a debug log, and it is
not part of detection. Nothing in a scan reaches it; the user must type the verb.
The boundary that keeps "report only, never remediate" true is ownership, not
read-only-ness:

- It writes exactly three names it owns — `~/.local/bin/surplies-notify`, and either
  `~/Library/LaunchAgents/com.surplies.notify.plist` or `surplies-notify.{service,timer}`
  under `$XDG_CONFIG_HOME/systemd/user`. It must never touch a file it did not create,
  and `remove` must delete only that same set.
- It must never act on a finding, and must never run as part of a scan.
- It stays in `internal/schedule`, not `internal/scan`. Detection code must not import it.
- Prerequisite checks run before anything is written, so a failed install leaves no files.
- External commands are invoked through the injected `run` func so tests never touch the
  real scheduler.


## Output rules

- **Roll up repeated diagnostics by cause.** Human-readable errors, coverage warnings, and scope notices must print each shared explanation once, followed by all affected paths in sorted order. Group coverage by category, then cause; normalize the affected path embedded in an explanation rather than repeating the same error for every filename. Preserve distinct evidence and causes. JSON retains the original individual records and exact details.
- **Distinguish scope from failures.** Expected limits such as shallow Git history are informational scope notices, not scan errors or attack indicators. Actual inspection failures remain warnings and qualify the final result as incomplete coverage.
- **Describe counters precisely.** Distinguish blobs considered by metadata from candidate blob bodies actually hashed. Zero candidate hashes must not imply that no Git objects were inspected.

## Citation hygiene

When adding or revising IOCs, keep these four places in sync. They drift independently and the drift is invisible until someone reads the README end-to-end.

1. **`ioc.go` block comments** — each IOC block names its specific writeup(s) with a working URL. If multiple sources contributed (e.g., StepSecurity for the campaign, Aikido for a hash, Socket for broader package coverage), name each one.
2. **README intro line** — `"Currently detects indicators from N documented major supply chain attacks, sourced from incident writeups by ..."`. The comma-separated source list and the attack count both need to match reality.
3. **README Acknowledgments** — both the "Sources, in rough order..." bullet list AND the per-writeup bulleted list under it must reflect every source actually used.
4. **README check tables** — the "Source attack" column on every affected table (`phantom-dependency`, `compromised-version`, `npm-payload-file`, `network-ioc-active-connection`, `project-artifact`, `compromised-python-version`, `compromised-composer-version`) must use the same campaign name the `ioc.go` comments use.

Other rules:

- **Only cite sources we actually pull IOCs from.** Outlets like Wiz, Snyk, Hacker News, Infosecurity Magazine may be useful in chat for confirming attribution, but they don't go in the README unless we used them for a specific IOC.
- **Sub-incidents are not separate attacks.** Same actor + same payload family + same exfil infrastructure = same campaign, even if the initial-access vector differs. Defer to how Socket / StepSecurity / the campaign's primary trackers frame it; don't infer "distinct attack" from a postmortem that doesn't name the campaign.
- **Attack-bullet style in the intro: one link in the title, no inline citations.** Match the axios/litellm pattern. Acknowledgments carries the full source credit. Inline links scattered through a paragraph read as "random citations."
- **Code spans inside link text break the underline on GitHub** and make a single link render as multiple visually-disconnected chunks. Move code spans outside the link text, or shorten the link to a trailing `([postmortem](url))` pointer.

## Reaching sources

Research tooling only — this has nothing to do with what the scanner itself may shell out to.

Writeups and tracker pages are often behind Cloudflare, which returns `403` to both `WebFetch` and `curl`. Use **agent-browser** (`preview_open` / `preview_navigate`, then `preview_evaluate`) to reach them. Once a page is open, `preview_evaluate` can also `fetch()` same-origin endpoints the page itself links to, which is how you get machine-readable data instead of prose.

- Socket's `supply-chain-attacks/<campaign>` tracker pages block `WebFetch` but load fine in the browser, and each exposes a full CSV at `/api/public/supply-chain-attacks/<campaign>/packages.csv` — every affected package with ecosystem and version, which is exactly what the version checks need.
- Prefer `preview_evaluate` returning parsed/aggregated values over dumping page text; a 400-row table wastes context as prose and reads cleanly as JSON.
- `WebFetch` summarizes through a small model, so it drops and occasionally garbles hashes, version numbers, and exact signature strings. It is fine for "does this page cover X," but re-read the primary with the browser (or `git clone` the dossier repo) before any hash or version lands in `ioc.go`.

## Structure

Go layout: the root is a thin `package main` so `go install github.com/astrostl/surplies@latest` keeps working; detection lives in `internal/scan` and the scheduling subcommand in `internal/schedule`.

- `main.go` — CLI entry point only: subcommand dispatch, flags, root collection, exit codes
- `embed.go` — `//go:embed` of `scripts/notify/*.sh`; the root owns these because an embed pattern cannot traverse up out of its own directory, and the scripts stay at the repo root for documented manual installation
- `internal/schedule/` — the `schedule` subcommand: launchd and systemd user-timer install, disable, remove. Takes the embedded scripts as a parameter; imports nothing from `internal/scan`
- `internal/scan/modes.go` — scan mode flags and default-scope help text
- `internal/scan/scanner.go` — orchestration, types, npm checks
- `internal/scan/report.go`, `report_print.go` — JSON report and human rendering
- `internal/scan/python.go` — Python/PyPI checks (site-packages, .pth files)
- `internal/scan/composer.go` — Composer/Packagist checks (vendor/composer/installed.json)
- `internal/scan/content.go` — content-based checks (payload signatures, fake-font detection, repo artifacts, patched npm CLI) for attacks that inject into a file that is supposed to exist under that name
- `internal/scan/content_scope.go` — which files are eligible for content inspection
- `internal/scan/assets.go` — disguised-asset header validation
- `internal/scan/heuristics.go` — loader/obfuscation/Unicode contextual checks
- `internal/scan/ioc.go` — known IOC database (bad versions, phantom packages, C2 indicators, artifact paths, payload hashes)
- `internal/scan/persistence.go` — targeted application entrypoints and sidecars, plus runtime/staging warnings
- `internal/scan/toolchains.go` — additional package-manager entrypoints
- `internal/scan/tasks.go` — JSONC-aware detection of automatic Node-to-font tasks and workspace settings context
- `internal/scan/startup.go` — shell startup, launch agents, systemd, cron and hosts content checks
- `internal/scan/network.go` — bounded netstat snapshot and DNS resolution
- `internal/scan/roots.go` — shared home/additional-root traversal, root symlink resolution, and overlap deduplication
- `internal/scan/git.go` — local Git ref/history inspection against the shared payload hash list; no fetch or checkout
- `internal/scan/testdata/` — benign fixtures, notably the genuine `Math_Symbol.js` whose filename collides with the keyv payload

### Payload hash tiers

`KnownRepoPayloadHashes` has two tiers and the difference is a published size. A sized entry is matched by exact length plus SHA-256 under any filename or extension. A size-less entry is matched by published filename only and is deliberately excluded from Git blob candidates, because a size-less entry must never mean "hash every blob in every repository". Where a source publishes a Git object identity, match it against the object ID directly, with no body read.

## Runtime scope decision (G15)

Keep live collection limited to the bounded `netstat` snapshot and DNS resolution
of the existing indicator list. Process ancestry/command-line/memory inspection,
Windows registry/task APIs, protocol capture and dynamic blockchain resolution
remain outside the scanner. Read-only Git inspection remains authorized
under its existing constraints. This decision adds no runtime commands or IOC.

## Agent scan runs

Run scanner invocations in tmux so long scans remain observable and survive a
tool-call timeout. Use the local `./surplies` build, capture stdout and stderr
to log files, and record the exit status. For performance investigations, use `-debug` and inspect the live log directly;
do not ask the user to relay diagnostic output the agent can collect itself.
Prefer inert fixtures or small, explicitly bounded directory samples. Do not
repeat whole-home scans to benchmark changes without explicit user approval.
Stop a live diagnostic run once it provides enough evidence; do not let a costly
scan finish merely to collect totals.

Regression requirement: a package manifest or dotfiles `.git` directory at
`HomeDir` must not implicitly classify its child trees (Documents, Library,
caches, Downloads) as project content. Test with home-level markers plus both
unrelated data and a genuine nested project before claiming scope fixes.

Routine content-read invariant: project membership, a source extension, or an
executable bit must never alone select a file for reading. Each ordinary read
must be a manifest, declared execution target, known persistence target, or a
candidate for a documented filename/config/font check. Regression tests must
place marker-bearing decoys inside real-looking projects and assert exact
content bytes, including with default modes and explicit roots.
