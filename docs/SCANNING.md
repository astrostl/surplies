# Scanning behavior and scope

What a default scan reads, what it deliberately does not read, and the reasoning
behind each limit. The principles these follow from are in the
[README](../README.md#design-principles); for the checks themselves see [Checks](CHECKS.md).

## Scan phases

The scanner runs six phases sequentially:

1. **Known malicious artifacts** — check fixed filesystem paths for dropped payloads, plus global npm and documented Electron application entrypoints and sidecars, including recursive persistence discovery under home and system roots and any `-root` directories; also warn on documented runtime/staging paths
2. **Directory scanning** — walk home, each additional `-root` directory, and the temp directories, inspecting every `node_modules` for compromised packages, every Composer `vendor/` for compromised packages, every `.claude/` / `.vscode/` for project-local payload files, and every build config, web font, and `.gitignore` encountered along the way for injected payload content. The same discovery walk collects Python environments and Git repositories for later phases, and matches the temp staging names at every depth beneath a temp root (`-skip-tmproots` drops the temp directories from this walk, keeping any named with `-root`, still matches the staging names at the top of each one, and reports a `scan-limited` notice); dependency checks select declared entrypoints and known payload candidates
3. **Python site-packages scanning** — inspect discovered `site-packages` directories plus system Python paths
4. **Running processes** — read running command lines for [`running-payload-process`](CHECKS.md#41-running-payload-process-critical); skipped entirely under `-only`
5. **Network IOCs** — check active connections from `netstat -n` against known C2 IPs; `-resolve` additionally looks up the known C2 domains and matches their current addresses; skipped entirely under `-only`
6. **Git payload hashes** — inspect blobs reachable from local refs/history against the active payload hash list (skipped entirely when the scan has already spent its stall budget: the storage is not answering, and a longer partial report is not what the reader needs)

## External commands

A scan executes exactly two external programs: `netstat` and `git`. Both are the
documented exceptions to filesystem-only detection; everything else a check knows
comes from reading files. No package manager or runtime (`npm`, `pip`, `python`,
`node`, `kubectl`, `docker`) is ever invoked, and nothing is run through a shell —
each command is executed directly with an argument vector, so no scanned path or
file content can be interpreted as shell syntax.

Running command lines are read without a command: `/proc` on Linux,
`proc_info`/`sysctl` on macOS, and the Toolhelp snapshot plus
`NtQueryInformationProcess` on Windows. Nothing is sent to, suspended in, or
attached to any process.

| Command | When | Exact invocation |
|---|---|---|
| `netstat` | Network IOC phase; skipped entirely under `-only` | `netstat -n`, plus `-l` on macOS, under a five-second deadline |
| `git` | Once at the start of the Git phase, to resolve and version-check Git | `git --version`, deliberately without the hardening flags an older Git would reject |
| `git` | Git history phase, per repository | `rev-parse --path-format=absolute --git-common-dir`, `rev-parse --is-shallow-repository`, `rev-list --objects --all --missing=print` (with `-z` on Git 2.50 or newer, `--no-object-names` below it), `cat-file --batch-check`, `cat-file --batch`, each under the repository's two-minute deadline |

Every Git command but the version probe is prefixed with `--no-pager
--no-replace-objects --no-lazy-fetch -c core.hooksPath=<null device> -c
core.fsmonitor=false -c protocol.allow=never -c core.commitGraph=false -c
safe.directory=* -C <repo>`, and runs with the inherited `GIT_*` environment
removed and `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<null device>`,
`GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0` and
`LC_ALL=C` set. That combination is what makes the Git phase read-only and
offline: no fetch, no checkout, no hook, filter or fsmonitor process, and no
repository, user or system configuration that could redirect the scan. Git is
resolved from `PATH` only. See [Default Git history checks](#default-git-history-checks).

Three more commands exist in the program and are unreachable from a scan. They
belong to the [`schedule`](../README.md#scheduled-scans) subcommand, which the user
must invoke by name: `launchctl` (`print`, `bootout`, `enable`, `bootstrap`,
`disable`) on macOS, and `systemctl --user` (`show-environment`, `daemon-reload`,
`enable`, `disable --now`, `restart`, `stop`) plus a `notify-send --version`
prerequisite probe on Linux. Detection code does not import `internal/schedule`.
The notification helper that `schedule` installs runs `surplies` itself and then
`osascript` or `notify-send` to display the result; it is a shell script under the
user's own account, not something the scanner calls.

## Default dependency checks

Every full scan checks installed package names and versions, declared execution targets, known payload candidates, and targeted persistence files. Dependency content inspection selects:

- npm: declared `main`, `module`, `bin`, and root `exports` execution targets (including common runtime conditions), with `index.js` as the default main when present.
- Python: modules declared by `console_scripts` / `gui_scripts` in installed `entry_points.txt`, plus signature inspection of startup `.pth` files.
- Composer: explicitly listed `autoload.files` from installed package metadata.
- Known artifact/hash candidate names, nested package metadata, project hooks and targeted persistence checks remain discoverable.

It does not recursively read transitive imports, wildcard/subpath exports,
TypeScript type exports, unreferenced dependency source, datasets or documentation.
Extracted uv caches and application bundles are also treated as installed code,
not general source trees. This selects evidence for the supported checks; it is
not an arbitrary-malware search through every installed byte. `-broad`
does not bypass dependency selection. No aggregate byte cutoff is used.

Git history checks also run by default and select candidates
by the known payload sizes before reading blob contents. Metadata traversal and
large declared entrypoints still cost work; no whole-home runtime is promised.

The human report ends with one verdict, coverage status, elapsed time and
content-read totals. Critical indicators, warnings requiring review, and
informational context appear separately. Related warnings share one explanation
with their paths underneath. The report includes grouped coverage failures with affected paths and scope-limit
counts after the findings. Routine excluded-path lists are kept out of terminal
output. Each human-mode run saves all findings, exact paths and scan statistics
to a private `surplies-report-*.json` file in the system temporary directory and
prints its path; no repeat scan is needed to retrieve details. Informational observations are not presented as attack
indicators. JSON retains all original records on stdout; a concise human summary
goes to stderr. Progress stays on stderr. For example:

```sh
surplies -json | jq '.[] | select(.severity == "CRITICAL")'
```

## Default Git history checks

The scanner discovers repositories under home and additional `-root` directories, including nested repositories, bare repositories and linked worktrees. It checks blobs reachable from all locally available refs (branches, remote-tracking branches, tags and HEADs) and their history against the shared [active payload hashes](ATTACKS.md#active-payload-hashes), regardless of filename. Loose and packed objects and SHA-1/SHA-256 Git repositories are supported. A matching historical blob is reported even when the checked-out branch is clean; it does not by itself prove execution or current infection.

Dependency checks, Git history checks, and coverage details are enabled by default; no mode flags are required.

Git is resolved from `PATH` only, and the resolved path and version are recorded in `stats` and printed on every Git-enabled run. Git 2.45 or newer is required, because every command below passes `--no-lazy-fetch`; an older Git fails the whole command line and inspects nothing, which is reported as a critical [`git-too-old`](CHECKS.md#26-git-too-old-critical) finding when repositories were found. The scanner uses [Git object enumeration](https://git-scm.com/docs/git-rev-list) and [raw blob reads](https://git-scm.com/docs/git-cat-file), with replacement objects and lazy fetching disabled. Object names are requested only in the NUL-framed `-z` form added in [Git 2.50](https://github.com/git/git/blob/master/Documentation/RelNotes/2.50.0.adoc), never in the legacy space-joined form a path can be mistaken for; an older Git is given `--no-object-names` and its missing filename-gated coverage is reported as a critical [`git-too-old-for-filenames`](CHECKS.md#27-git-too-old-for-filenames-critical). It does not fetch remote refs, check out branches, run hooks, apply text conversion or content filters, or modify repositories. Repo discovery follows the normal root symlink policy; internal directory symlinks are not traversed. The saved report is self-contained: alongside `invocation`, `stats` and `findings` it carries a `summary` field holding the same human-readable block the run printed to the terminal, verbatim — including the coverage banners. A reader who only has the JSON (an MDM inventory record, a ticket attachment) gets the plain-language verdict without re-deriving it. Repositories outside the selected roots need `-root`; a scan that finds none says so and names `-root`. System and global Git configuration are disabled for every invocation so that no external configuration can redirect the scan; because that also removes the scopes Git accepts `safe.directory` from, the scanner passes `-c safe.directory=*` itself. Without it a scan running as a different user than the repository owner — the normal case when an MDM policy runs as root over user home directories — fails Git's ownership check on every repository, which counts them as found but never scanned.

Blob selection has two independent halves. A published size or object identity needs no name and reaches a renamed dropper. A committed name the project walk would have opened — a payload or artifact filename, `.gitignore`, a `*.config.*` JavaScript file, a documented injectable source name, a font, a `.vscode`/`.claude` settings file — selects the blob for the identity-based content checks, mirroring the filesystem selection rule rather than the broader signature-eligibility rule; a source extension never alone selects a blob. The general heuristics stay on the working tree, because history carries every revision and would repeat each one. Repeated hits roll up to one finding per indicator per repository with a revision count. See [`git-payload-hash`](CHECKS.md#25-git-payload-hash-critical).

Only locally available reachable history is covered. Unfetched remote branches, missing shallow history, reflog-only/unreachable objects, uninitialized submodules and Git LFS content stored outside Git blobs are not cleared by this check. Each repository has a two-minute inspection deadline; candidate blob reads retain the exclusive 100 MB content limit. Known exact sizes avoid reading unrelated blob bodies; every candidate is verified by raw-content SHA-256. Shallow repositories produce informational `scan-limited` notices describing the available-history scope; these are not scan errors and do not change the exit status. Git absence, incompatible Git, broken refs, missing objects and command failures produce `scan-incomplete` warnings and nonzero exit status. Their share of the repositories found is then judged as a whole: no repositories found is a warning, and more than 25% unscannable — including every run that completed none of them — is a critical coverage verdict that exits 2, because at that point the Git result no longer describes the machine. Ordinary breakage across a deployed fleet stays well under that share; the machines whose Git scan meant nothing failed nearly all of their repositories. When objects are missing, available reachable objects are still inspected, and the repository remains incomplete. Findings identify the repository, blob ID and SHA-256, with a `git log --all --find-object=<blob>` command for investigating paths/commits. Summary counts distinguish found/completed repositories, blobs considered by metadata, candidate blobs actually hashed, and blobs read because their committed name selected them. Zero candidate blobs can simply mean no blob matched a known payload size; the summary counts object-identity matches separately from hashed candidates.

Discovery recognizes [uv’s deliberately empty Git cache marker](https://github.com/astral-sh/uv/blob/main/crates/uv-cache/src/lib.rs) only in a versioned sdist bucket with the accompanying empty `.gitignore` and cache signature. It still searches inside that bucket for actual repositories; other invalid gitfiles remain errors.

## Routine content scope

Routine scans select files for specific checks:

- package manifests, lifecycle targets and declared deep entrypoints;
- startup/toolchain/application persistence targets and known artifact/hash candidates;
- documented injection filenames (`App.js`, `index.js`, `truffle.js`, `tasks.json`, `cli.js`, `plugin.js`, `api_manager.js`, `generate.js`), JavaScript/TypeScript `*.config.*`, and direct `.claude`/`.vscode` settings;
- project font files for the fake-font check (recognized headers do not require body reads).

Project membership, `-root`, a source extension, or an executable bit **does not**
make arbitrary file contents eligible. A home-level manifest cannot turn the
home directory into a content sweep. Directory metadata is still traversed to
find packages and candidates. Broad generic source/text inspection is available
only through the separately explicit `-broad` option. Browser caches require
`-browser-cache`; raw npm stores require `-npm-cache`. All three options are off
by default. Dependency selection stays
targeted even with `-broad`.

Coverage details, dependency inspection, and Git history checks are the default. No aggregate byte cutoff is used. Selection limits
are reported as scope notices; this does not promise to detect arbitrary malware
in unselected files. No whole-home runtime is claimed from fixture measurements.

Native Mach-O/ELF headers are recognized before applying the text-file size limit;
the binary bodies are outside source-signature inspection, rather than oversized
source failures. Known exact-hash candidates still receive full candidate reads.
A lifecycle script whose target file is not installed is reported as
`missing-script-target` informational context, not as a read failure: published
tarballs routinely strip build hooks and pruned installs drop install helpers.
Because it fires across dozens of packages on an ordinary machine, the human
report prints the explanation once and counts the packages; every individual
path stays in `-json` and the saved report. Actual read failures remain
coverage errors. Non-npm update manifests are not parsed as npm versions merely because
they are named `package.json`.

## Content I/O reporting

Default scans include dependency inspection, Git history checks, and coverage details, with dependency reads selected by manifests and known candidates rather than every eligible dependency file. Selected general source checks exclude binary bodies after an 8 KiB prefix rather than reading an entire extensionless cache object before discovering that it is binary. Text candidates retain whole-file checks within the existing size/time limits. Known exact-hash filenames, lifecycle targets, selected package metadata and targeted persistence entrypoints keep their existing inspection policy. Recognized assets still need only their headers; leading NUL/whitespace padding does not prevent inspection of disguised script assets.

The summary line reports bytes returned by content-file reads, files checked, and the number of binary files skipped. The count includes prefix and failed reads, but excludes filesystem metadata, OS read-ahead and Git subprocess I/O; it is not a replacement for Activity Monitor's process I/O counter. Verbose output also reports cumulative content reads and the current path approximately every GiB. Each skipped binary file has its own scope notice, so the saved report and `-json` name exactly the files the summary counts; the terminal shows only their number.

## Raw npm cache policy

Full scans skip directories named `_cacache` **before enumerating their contents**, across project, Python, persistence and Git discovery. This avoids reading npm's opaque content-addressed HTTP/package storage as though every object were installed source. The distinction from npx's executable installation cache follows [npm's cache documentation](https://docs.npmjs.com/cli/v11/commands/npm-cache/).

Each excluded store is logged immediately and appears once as an informational `scan-limited` record in text/JSON output. This is an explicit coverage exclusion, not a claim that cached data is safe. An explicitly added `-root` does not override it. Use `-npm-cache` to opt into raw cache inspection; full scans do not enable this expensive option. Archives still are not unpacked.

Installed `node_modules` and `.npm/_npx` installations retain metadata/lifecycle checks and deep declared-entrypoint inspection. Executable plugin caches retain source checks outside dependency boundaries. Extracted uv package bodies are not broadly read; known candidate names and nested installed-package metadata remain discoverable.

## Expanded checks and scope decisions

| Check / coverage | Behavior | Evidence |
|---|---|---|
| Network collection | Five-second collector/resolver deadline; errors and timeouts are `scan-incomplete`. NXDOMAIN and successful but filtered/empty DNS answers have distinct `scan-limited` notices. Only established TCP **remote** endpoints match; listeners, local addresses, other connection states and UDP are outside this snapshot check. IPv4-mapped IPv6 normalizes to IPv4. | Local correctness fixes; existing C2 indicators unchanged. |
| Package metadata and lifecycle targets | Project and installed manifests are parsed with bounded reads. Invalid/unreadable manifests and selected missing scripts report incomplete coverage. Hooks: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepack`, `postpack`. Quoted JS/CJS/MJS targets are supported; arbitrary shell syntax and options are not interpreted. Generic obfuscation is WARN, not proof of infection. | [npm lifecycle semantics](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [OSM task/lifecycle analysis](https://opensourcemalware.com/blog/how-malware-abuses-npm-lifecycle-scripts-and-vs-code-tasks), [NIK CI source](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/ci/scan_repo.sh). |
| `loader-variant`, `loader-structure`, `correlated-loader-markers` | Quote/spacing variants, immediate local-CJS loader calls, and markers correlated with loader/decode structure produce WARN. Generic `createRequire`, dates, and extra marker names alone do not. | [ByteGuard rules](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json); community-pattern evidence. |
| Additional toolchains | Targeted npm `bin/npm-cli.js`, Yarn `lib/cli.js`, Corepack `dist/pnpm.js`, pnpm `bin/pnpm.cjs`, npx-cached `pnpm.cjs`, and Claude version files are inspected by default, within home, added roots, and existing system persistence roots. Presence/size alone is not a finding for these added targets. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts); defensive discovery, not independent infection confirmation for every product. |
| `disguised-file-execution-task`, `workspace-setting-context` | Broader interpreters and binary-named targets warn, including manual tasks and platform overrides. Automatic Node-to-font remains CRITICAL. Ordinary automatic builds and hidden output alone are not flagged. Settings are context; invalid values are INFO. Multiple risky/contextual preferences warn without claiming a trust bypass. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts), [Microsoft task semantics](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior). |
| `startup-content`, `hosts-c2-entry` | Inspect shell startup files, macOS launch directories, Linux systemd/cron locations, and the system hosts file for contextual known indicators. Comments are ignored. Binary plists produce an explicit scope notice; no plist decoder or external command is invoked. Windows startup APIs/registry enumeration remain outside scope. | [NIK macOS](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_macos.sh), [NIK Linux](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_linux.sh); community hunts, not PolinRider attribution. |
| `asset-format-mismatch` | WARN for unsupported/truncated headers or text in PNG/JPEG/GIF/WebP/ICO/WASM/PDF/ZIP/MP3/MP4. Headers are format hints, not full validators. Bounded whitespace/NUL padding is removed for script inspection. Existing font magics and HTML/XML download-error exclusions remain. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts). |
| `unicode-concealment`, `escaped-execution`, `suspicious-source-execution` | WARN for unbalanced bidi controls, ASCII-identifier joiners, runs of at least eight variation selectors in either Unicode range, correlated escaped execution, decode/execute, download-to-shell, or hidden detached spawn structure. No long-line cutoff. Ordinary emoji, balanced RTL, international joiners, private-use glyphs, `eval` alone and public RPC URLs alone do not trigger these general-source checks. | [Endor Labs](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode), [Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode), [ByteGuard rules](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json). |

Live telemetry decision (G15): retain the bounded network snapshot, and read running command lines only to match indicators the scanner already holds on disk (see [`running-payload-process`](CHECKS.md#41-running-payload-process-critical)). Process ancestry, registry and scheduled-task APIs, memory, protocol capture, and dynamic blockchain queries are deferred to complementary endpoint/network investigation. No C2 connections, remediation, or account actions are added. Static findings do not establish execution; a clean scan cannot rule out a running or historical implant.

Explicit package checks follow package-directory symlinks (including pnpm layouts). The scanner resolves requested root symlinks and follows selected file symlinks, but does not recursively follow internal directory symlinks. Supply their destinations with `-root`. Directory traversal itself is not subject to the per-file processing deadline. Cloud-sync placeholders are recognised from the stat the read already makes and skipped unread, so a scan never downloads a file to inspect it. A directory or file that macOS refuses to materialize for the scan fails with `resource deadlock avoided` (`EDEADLK`) and is reported under `not downloaded` rather than as an unexplained error; a read that hangs anyway costs five seconds, and one minute of such reads across the whole run stops content reading and the Git phase entirely. Package-target checks can inspect a lifecycle target separately from an earlier ordinary source read; repeated identical findings are deduplicated.

## Performance diagnostics

Directory discovery is shared across project, Python, and Git checks. Content reads
use a 32 MiB in-memory cache shared by checks, with file identity, size, modification
time, and mode checked before reuse. Eviction causes a fresh read; it never excludes
a file from inspection. Separate installed copies remain independently checked.
Debug reports distinguish actual reads from content cache hits (`CacheHits`).

Run `./surplies -q -debug` for a quiet terminal and a detailed debug log.
The private log path is printed alongside the saved report. Without `-q`, debug
output is also echoed to stderr.
`-debug` does not change scan coverage and is not enabled by default. It writes
paths and measurements to the log, leaving JSON findings on stdout unchanged.
The log records directory traversal, each file's open/read/inspect steps,
bytes read, read and inspection durations, timeouts, stage timings, and the
20 directories with the greatest processing time and bytes read. Directory
rows count direct files; nested lifecycle inspection times can overlap.
Live entries remain available if a scan is interrupted; totals print at normal
completion. Logging adds overhead, so diagnostic timings are approximate.
Bytes exclude filesystem metadata, OS read-ahead, and Git subprocess I/O.
No file contents are logged.

Saved human-run reports also include `stats.debug`: per-file bytes, read counts,
check selection reasons, directory/package byte totals, stage durations, directory
enumeration calls/entries/errors and elapsed time, and Git command durations and
stdout/stderr byte counts. Selection reasons record explicit dependency selection
or the scanner check call chain. Git pipe bytes are not disk-read bytes.
On macOS, debug reports include OS-accounted disk read/write bytes from
[`proc_pid_rusage`](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/libproc/libproc.c).
Scanner totals are deltas during scanning, with separate deltas for each stage.
Git commands have final lifetime measurements collected after exit but before
reaping, including short-lived commands. Scanner and child counters remain
separate; unavailable measurements carry an error and are not reported as zero.
These OS disk counters differ from logical file-content reads and pipe traffic.
They exclude final report serialization and may differ from Activity Monitor's
sampling window. Other platforms currently report disk-byte counters unavailable.
No cache purge, privileged helper, or additional content reading is performed
for these measurements.
