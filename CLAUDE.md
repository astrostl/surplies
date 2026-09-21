# surplies

## Talking to the developer

Keep it short. A few sentences beats a page. No tables, no status matrices, no
recaps of what you just did.

- Answer the question asked. Do not volunteer adjacent concerns.
- Do not list caveats, tradeoffs, or options unless asked. Pick one and say it.
- Never claim something works until it has been verified against real bytes.
  A fixture you wrote that fires an existing rule proves nothing.
- If you were wrong, say so in one line and move on.

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

## Naming in program output

Every name a finding prints must be one the reader can search for and land on a
public writeup: the campaign, the package, the landing. Private incident
codenames, internal document titles, and mechanic-level shorthand
(`cls`, `clb`, `A9-9034`) mean nothing outside this repo and belong in source
comments, where the provenance pointer is useful. Where two variants of one
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

## Reaching sources

Writeups and tracker pages are often behind Cloudflare, and `WebFetch` garbles hashes and version strings. See the `reaching-sources` skill before a value from a writeup lands in `ioc.go`.

## Structure

Go layout: the root is a thin `package main` so `go install github.com/astrostl/surplies@latest` keeps working; detection lives in `internal/scan` and the scheduling subcommand in `internal/schedule`.

- `embed.go` — `//go:embed` of `scripts/notify/*.sh`; the root owns these because an embed pattern cannot traverse up out of its own directory, and the scripts stay at the repo root for documented manual installation
- `internal/scan/testdata/` — benign fixtures, notably the genuine `Math_Symbol.js` whose filename collides with the keyv payload

Documentation: `README.md` is the human-legible overview (what it is, what it
detects, install, usage, the design principles, a one-line-per-check table).
Detail lives under `docs/` — `ATTACKS.md` (campaigns and the active hash list),
`CHECKS.md` (all 26 checks), `SCANNING.md` (scan phases, selection and scope
decisions, performance diagnostics), `ATTRIBUTION.md` (sources). Keep the README
short; new detail belongs in the matching `docs/` file.

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

For a quick real run against the built binary, use `-only` with whatever roots
you want to look at — `-root /tmp -only`, a fixture directory, a single project.
`-only` confines the scan to the named roots: live connections and the system
Python paths are skipped outright, and every fixed-path check (artifacts,
persistence roots, npm CLI, startup files, temp dirs) runs only where its
candidate falls inside a requested root. `-only` also puts the first `-root` in
home's place, so home-relative candidates resolve inside that tree. It finishes
in milliseconds and never walks the user's home directory. Use it for
rapid iteration and one-off checks. Do not use it to claim a machine is clean:
a `-only` run that finds nothing says nothing about persistence, artifacts, or
connections. Never point a default (non-`-only`) run at the user's home without
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
