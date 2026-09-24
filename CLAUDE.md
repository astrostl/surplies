# surplies

## Talking to the developer

Keep it short. A few sentences beats a page. No tables, no status matrices, no
recaps of what you just did.

- Answer the question asked. Do not volunteer adjacent concerns.
- Do not list caveats, tradeoffs, or options unless asked. Pick one and say it.
- Never claim something works until it has been verified against real bytes.
  A fixture you wrote that fires an existing rule proves nothing.
- If you were wrong, say so in one line and move on.
- Never be verbose, including when asked to expand. "More detail" means one more
  layer on the same short answer, not pages. Add a paragraph, not a document.
  Headers and multi-section writeups are almost never the right shape for a reply.
- Plain human summaries by default. The developer will ask for more if it is too
  simple; that is cheaper than making them read past what they needed.
- "cpm" means commit and push to `main`.
- Avoid semicolons in phrasing where reasonably possible. This is strict for
  replies and for `-h` help text (flag descriptions, usage lines, the help
  header). Use two sentences or a plain conjunction instead. Existing
  semicolons in finding text and docs don't need a sweep.

## Design principles

- **Filesystem-only detection.** Never shell out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any other tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scan files on disk instead. The exceptions are `netstat` for live network connection IOC matching, the running-process list read through OS process interfaces (`/proc`, `sysctl`/`proc_info`, the Windows process APIs — never an external command), and default Git history scans using read-only Git plumbing to inspect locally available refs and raw objects. Git scans must never fetch (including lazy fetching), check out files, execute hooks/filters, or modify repositories. The `schedule` subcommand additionally runs `launchctl`, `systemctl --user`, and `notify-send`; this is outside detection entirely and is covered by the scheduling carve-out below.
- **Report only, never remediate.** surplies is a read-only scanner. A scan must never delete files, uninstall packages, modify configs, or take any corrective action in response to a finding. Findings are reported; the user decides what to do. See the scheduling carve-out below for the single, explicitly invoked exception.
- **No container/orchestrator checks.** Do not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem rooted at the user's home directory and explicitly added `-root` directories (plus well-known system paths for artifact checks).
- **Cross-platform.** All checks must work on macOS, Linux, and Windows (amd64 and arm64). Use `runtime.GOOS` for platform-specific paths; never assume a single OS. Two things outside detection are deliberate exceptions. The `schedule` subcommand supports macOS and Linux only and refuses cleanly elsewhere, because Windows has no equivalent user-level scheduler already covered by the embedded helpers. The ENTER wait for a double-clicked window is Windows-only, because only Windows destroys the console window when the process exits; see the carve-out below.
- **Zero dependencies.** stdlib only. No third-party Go modules. Git history inspection requires Git 2.45 or newer (the release that added `--no-lazy-fetch`), resolved from `PATH` and never hunted for elsewhere: a fallback would have a root-context scan execute a binary out of a user-writable directory. An older Git inspects nothing, so it is a critical `git-too-old` finding when repositories were found, never a silent skip. Reading the names blobs were committed under additionally needs Git 2.50 (`rev-list -z`); object names must only ever be parsed in that NUL-framed form, never the legacy space-joined one, and a Git between 2.45 and 2.49 runs the size-matched half alone as a critical `git-too-old-for-filenames`. The version probe must stay a bare `git --version` without the hardening flags, which the Git it identifies would reject.
- **Citation-required IOCs.** Only add checks for attacks that the developer explicitly requests with a linked, referenced source. Never speculatively add IOCs or checks from general knowledge.

### Scheduling subcommand

A scan writes only its own `surplies-report-*.json` (and, with `-debug`, its
debug log) in the system temporary directory. `surplies schedule` is the only code
path that writes anything else, and it is not part of detection. Nothing in a scan reaches it; the user must type the verb.
The boundary that keeps "report only, never remediate" true is ownership, not
read-only-ness:

- It writes only files it owns — `~/.local/bin/surplies-notify`, plus
  `~/Library/LaunchAgents/com.surplies.notify.plist` on macOS or
  `surplies-notify.{service,timer}` under `$XDG_CONFIG_HOME/systemd/user` on Linux —
  creating their parent directories (and `~/Library/Logs` for launchd's output) if
  missing. It must never touch a file it did not create, and `remove` must delete
  only that same set.
- It must never act on a finding, and must never run as part of a scan.
- It stays in `internal/schedule`, not `internal/scan`. Detection code must not import it.
- Prerequisite checks run before anything is written, so a failed install leaves no files.
- External commands are invoked through the injected `run` func so tests never touch the
  real scheduler.


### Double-clicked window wait

A double-clicked `surplies.exe` prints its whole report into a console window
that conhost destroys on exit. The root `pause*.go` files wait for ENTER so
the reader can see it. This is terminal UX, not detection, and a scanner that
blocks forever on an unattended machine is worse than one whose window closes,
so every condition below holds before anything waits:

- This process is the only one attached to its console (`GetConsoleProcessList`
  returns 1). A shell, a scheduled task and a service all fail that test, and
  `ownsConsole` is a `false` stub on every platform but Windows.
- stdin and stdout are both still character devices, so any redirected, piped
  or `-json` run returns immediately.
- Neither `-no-pause` nor `SURPLIES_NO_PAUSE` is set.
- The wait itself is bounded at one minute. Do not make it unbounded.

It stays in `package main` at the root, runs after the report is printed, and
must never change the exit code or be reachable from `internal/scan`.

## Output rules

- **Roll up repeated diagnostics by cause.** Human-readable errors, coverage warnings, and scope notices must print each shared explanation once, followed by all affected paths in sorted order. Group coverage by category, then cause; normalize the affected path embedded in an explanation rather than repeating the same error for every filename. Preserve distinct evidence and causes. JSON retains the original individual records and exact details.
- **Distinguish scope from failures.** Expected limits such as shallow Git history are informational scope notices, not scan errors or attack indicators. Actual inspection failures remain warnings and qualify the final result as incomplete coverage.
- **Describe counters precisely.** Distinguish blobs considered by metadata from candidate blob bodies actually hashed. Zero candidate hashes must not imply that no Git objects were inspected.

## Naming in program output

Every name a finding prints must be one the reader can search for and land on a
public writeup: the campaign, the package, the landing. Private incident
codenames, internal document titles, and mechanic-level shorthand
(`cls`, `clb`, `A9-9034`) mean nothing outside this repo, and they do not
belong in source comments either — see **Sources** below. Where two variants of one
campaign need distinguishing, name them by what the reader can see — the
carrier or the landing (Fake Font, config-append) — not by wave, date, or
attacker build tag. Attacker-internal strings may appear as evidence inside a
detail, never as the label the finding is identified by.

**Use the published name, not a paraphrase of it.** If a writeup already named
the landing or variant, that exact name is the one to print, because it is what
the reader will search. Invent a descriptor only where no public name exists.
`Fake Font` is OpenSourceMalware's name for the `tasks.json` `folderOpen` +
`fa-solid-400.woff2` landing; writing "fake-font dropper" instead loses the
search hit for no gain.

**Scope a corroboration caveat to the thing that actually lacks support.** An
indicator is usually a mix: a publicly documented technique plus one
incident-sourced value. "No public corroboration" attached to the whole finding
tells the reader the attack is unverified, which is false and invites them to
dismiss it. Name the element — "this sample's hash is incident-sourced" — and
say plainly that the surrounding mechanism is documented. The same precision
applies in the README and under `docs/`.

## Citation hygiene

When adding or revising IOCs, keep the `ioc.go` block comments and all four documentation locations in sync. See the `citation-hygiene` skill.

### Sources

Cite only public, linkable sources. Nothing in this repository — code, comments,
`README.md`, `docs/`, this file, commit messages — may name or fingerprint
anything outside it: no external paths, no repository or organization names, no
document titles or digests. An indicator whose only support is non-public is one
to raise with the developer rather than annotate.

## Reaching sources

Writeups and tracker pages are often behind Cloudflare, and `WebFetch` garbles hashes and version strings. See the `reaching-sources` skill before a value from a writeup lands in `ioc.go`.

## Structure

Go layout: the root is a thin `package main` so `go install github.com/astrostl/surplies@latest` keeps working; detection lives in `internal/scan` and the scheduling subcommand in `internal/schedule`.

- `embed.go` — `//go:embed` of `scripts/notify/*.sh`; the root owns these because an embed pattern cannot traverse up out of its own directory, and the scripts stay at the repo root for documented manual installation
- `pause.go`, `pause_windows.go`, `pause_other.go` — the double-clicked window wait; terminal UX, so it belongs to the CLI and not to `internal/scan`
- `internal/scan/testdata/` — benign fixtures, notably the genuine `Math_Symbol.js` whose filename collides with the keyv payload

Documentation: `README.md` is the human-legible overview (what it is, what it
detects, install, usage, the design principles, a one-line-per-check table).
Detail lives under `docs/` — `ATTACKS.md` (campaigns and the active hash list),
`CHECKS.md` (all 41 checks), `SCANNING.md` (scan phases, selection and scope
decisions, performance diagnostics), `ATTRIBUTION.md` (sources). Keep the README
short; new detail belongs in the matching `docs/` file.

### Payload hash tiers

`KnownRepoPayloadHashes` has two tiers and the difference is a published size. A sized entry is matched by exact length plus SHA-256 under any filename or extension. A size-less entry is matched by published filename only and is never a size-derived Git blob candidate, because a size-less entry must never mean "hash every blob in every repository"; it reaches history only via the filename gate, which mirrors the filesystem selection rule (`targetedContentFile`/`injectionContentFile`) and never the broader `shouldScanForSignatures` eligibility test. History runs identity-based checks only — the general heuristics stay on the working tree, because history carries every revision of every file. Where a source publishes a Git object identity, match it against the object ID directly, with no body read.

## Runtime scope decision (G15)

Keep live collection limited to the bounded `netstat` snapshot, DNS resolution
of the existing indicator list, and a read of running command lines matched
only against indicators the scanner already holds on disk (Node running a
font-extension file, a `*.inz.cjs`/`*.inz.orig` sidecar argument, the running
Node script against the payload hash and signature lists). The process read
uses OS interfaces, runs no command, and never signals, suspends, or touches a
process. Process ancestry and memory inspection, Windows registry/task APIs,
protocol capture and dynamic blockchain resolution remain outside the scanner.
Read-only Git inspection remains authorized under its existing constraints.

## Agent scan runs

Run scanner invocations in tmux so long scans remain observable and survive a
tool-call timeout. Use the local `./surplies` build, capture stdout and stderr
to log files, and record the exit status. For performance investigations, use `-debug` and inspect the live log directly;
do not ask the user to relay diagnostic output the agent can collect itself.
Prefer inert fixtures or small, explicitly bounded directory samples. Do not
repeat whole-home scans to benchmark changes without explicit user approval.
Stop a live diagnostic run once it provides enough evidence; do not let a costly
scan finish merely to collect totals.

Clean up after yourself. Delete every scratch file and directory you create
under the system temp directory (logs, status files, fixture trees, copied
outside repositories, report JSON, tmux sockets) before the task ends. Leftovers
pollute later scans of that same temp directory and read as findings.

For a quick real run against the built binary, use `-only` with whatever roots
you want to look at — `-root /tmp -only`, a fixture directory, a single project.
`-only` confines the scan to the named roots: the live connection and process
snapshots are the only checks skipped outright, and every fixed-path check
(artifacts, persistence roots, npm CLI, startup files, system Python paths,
temp dirs) runs only where its candidate falls inside a requested root. `-only` also puts the first `-root` in
home's place, so home-relative candidates resolve inside that tree. It finishes
in milliseconds and never walks the user's home directory. Use it for
rapid iteration and one-off checks. Do not use it to claim a machine is clean:
a `-only` run that finds nothing says nothing about persistence, artifacts,
connections, or running processes. Never point a default (non-`-only`) run at the user's home without
being asked.

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
