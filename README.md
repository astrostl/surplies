# surplies

[![Go Report Card](https://goreportcard.com/badge/github.com/astrostl/surplies)](https://goreportcard.com/report/github.com/astrostl/surplies)

> **Disclaimer:** This tool is vibe coded and provided as-is, without warranty or guarantee of any kind. It may produce false positives, miss indicators, or behave unexpectedly. Use it as one signal among many, not as a definitive security verdict. Testing has only been performed on macOS — Linux and Windows behavior is untested.

A cross-platform CLI tool that scans your home directory (and well-known system Python paths) for evidence of supply chain attacks via compromised dependencies. Pure Go, no third-party Go modules. Git-history checks require Git.

**Currently detects indicators from seven documented major supply chain attacks**, sourced from incident writeups by [StepSecurity](https://www.stepsecurity.io/), [Socket](https://socket.dev/), [OpenSourceMalware](https://opensourcemalware.com/), [Aikido](https://www.aikido.dev/), [Endor Labs](https://www.endorlabs.com/), [SafeDep](https://safedep.io/), [Snyk](https://snyk.io/), and the [TanStack](https://tanstack.com/) team, plus registry advisory data from [OSV](https://osv.dev/) and the community [NullReceiver IR kit](https://github.com/OsamaCodes62/nullreceiver-ir-kit) and [ByteGuard](https://github.com/n0m4dz/ByteGuard) (see [Acknowledgments](#acknowledgments)). The [active hash list](#active-payload-hashes) also includes an explicitly requested, locally verified DUNE incident sample within the existing PolinRider campaign; its exact hash is incident-sourced, not independently publicly corroborated:

- **[GlassWorm Unicode concealment](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode)** — contextual source warnings for long variation-selector sequences and related Unicode concealment. These warnings do not attribute a file to GlassWorm or DUNE.
- **[axios npm compromise](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)** — compromised maintainer account published `axios@1.14.1` and `axios@0.30.4` with a phantom dependency (`plain-crypto-js`) that deployed a cross-platform RAT
- **[litellm PyPI compromise](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel)** — malicious `litellm@1.82.7` and `1.82.8` harvested credentials (SSH, AWS, GCP, Azure, env files) and installed a persistent C2 backdoor via systemd
- **[TrapDoor crypto-stealer campaign](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)** (attributed to GitHub actor `ddjidd564`, campaign marker `P-2024-001`, May 2026) — 34 purpose-built phantom packages across npm (21), PyPI (7), and Crates.io (6) impersonating crypto / DeFi / AI developer tooling. npm packages drop `trap-core.js` (48 KB, XOR-encrypted with key `cargo-build-helper-2026`) via `postinstall`, which writes `.cursorrules` and `CLAUDE.md` into the project directory for AI-assistant-driven persistence and pulls runtime config from `ddjidd564.github.io/defi-security-best-practices/`. surplies covers the npm and PyPI phantoms; Crates.io is out of scope (no Cargo scanner today).
- **[Mini Shai-Hulud campaign](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)** (attributed to TeamPCP, April–May 2026) — an ongoing self-spreading credential-theft worm across npm, PyPI, and Composer. The bulk of the campaign uses compromised maintainer accounts with "double-tap" publishing across `@uipath/*`, `@squawk/*`, `@tallyui/*`, `@mistralai/*`, `safe-action`, `@cap-js/*`, `intercom-client`, PyPI `lightning`/`guardrails-ai`/`mistralai`, Composer `intercom/intercom-php`, and many more. On May 11 a distinct sub-incident hit 42 `@tanstack/*` packages (84 versions) via a different initial-access vector: a fork PR poisoned a GitHub Actions cache, then an attacker-controlled binary extracted an OIDC token from runner memory and published directly to npm — same campaign payload family (`router_init.js`, Session-network exfil via `filev2.getsession.org` / `seed{1,2,3}.getsession.org`, self-propagation), different door in. On May 19 the campaign struck again with the AntV maintainer compromise: 317 packages across `@antv/*`, `@lint-md/*`, and AntV-adjacent unscoped (`echarts-for-react`, `timeago.js`, `size-sensor`, and the rest of the visualization-ecosystem surface) published with the same "double-tap" pattern, a new `@antv/setup` phantom pulled from `github:antvis/G2#<imposter-commit-sha>`, a new C2 endpoint (`t.m-kosche.com`, disguised as OpenTelemetry traces), and a new kitty-monitor persistence variant (`~/.local/share/kitty/cat.py` + `kitty-monitor.{service,plist}`) — same Mini Shai-Hulud toolkit (Bun runtime, hex obfuscation, `firedalazer` GitHub dead-drop trigger, Dune-themed exfil repo naming) per SafeDep's writeup. On June 1 the campaign hit 31 `@redhat-cloud-services/*` packages, published after an attacker minted an npm token from a GitHub Actions OIDC credential stolen from the `RedHatInsights/javascript-clients` repo — same payload family (`preinstall` → `node index.js` → encrypted Bun loader harvesting GitHub Actions secrets, npm tokens, cloud/Kubernetes/Vault material, and SSH/Git credentials). Notably, this wave exfiltrates over a legitimate, non-actor-owned endpoint rather than dedicated C2 infrastructure, so no new network IOC is added; per Socket's writeup.
- **[keyv npm compromise](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)** (August 4, 2026) — compromised release path for maintainer `jaredwray` published 11 malicious releases across `keyv@6.0.0`, `@cacheable/*`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, and `ecto@5.0.1`. Each tarball adds `"preinstall": "node setup.mjs"` plus two payload files (`setup.mjs` 29,918 bytes; `Math_Symbol.js` 727,680 bytes, byte-identical across all affected releases). A second execution path injected Claude Code `SessionStart` and VS Code `folderOpen` hooks (`.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/setup.mjs`) into the keyv repository. The malicious `keyv@6.0.0` release carried valid npm trusted provenance signed by GitHub Actions.
- **[PolinRider campaign](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)** (North Korea / DPRK, part of the Contagious Interview cluster; ongoing since December 2025) — a worm that spreads through developers rather than through a registry. It appends an obfuscated JavaScript loader to a real build config after ~280 spaces of padding, so the file still builds and still looks untouched in a diff; hides the same loader inside files named like web fonts, most often `public/fonts/fa-solid-400.woff2`, which reviewers and scanners skip as binary; and auto-executes via a `.vscode/tasks.json` task with `"runOn": "folderOpen"` the moment the project is opened in VS Code or Cursor. Once resident it harvests credentials, then propagates locally — `temp_auto_push.bat` resets the clock, amends the last commit so the timestamp matches the one it replaced, and force-pushes with cached git credentials, so GitHub sees the real developer. That reaches npm, Packagist, Go, and PyPI through whatever the victim maintains. Confirmed footprint is 4,367 repositories across 2,152 owners. The loader resolves its C2 off the Ethereum blockchain (the NullReceiver technique: the IP is encoded in the destination address bytes of a zero-value transaction), so there is no domain or host to seize. It also overwrites the global `npm/lib/cli.js` with a ~1 MB malicious CLI, which re-spawns the payload on every `npm` invocation and survives reboots and credential rotation, and patches Electron editors themselves — `@vscode/deviceid/dist/index.js` under VS Code, Cursor, and Antigravity, and GitHub Desktop's `main.js`, each rewritten to load a `*.inz.cjs` sidecar. Surplies checks documented application entrypoints and adjacent sidecars in conventional system and user installations, including `/Applications` on macOS, by default. It also checks Discord desktop core and small npm loader stubs. Custom installations and archived application code are not exhaustively covered; a clean scan is not proof that a host was never compromised.

## Design principles

- **Filesystem-first detection.** Never shells out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any package manager/runtime tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scans files on disk instead. The exceptions are `netstat` for live network connection IOC matching and Git history scans using read-only Git plumbing on local repositories. Git scans never fetch, check out files, or run repository code/hooks/filters.
- **Report only, never remediate.** Read-only scanner. Never deletes files, uninstalls packages, modifies configs, or takes any corrective action. Findings are reported; the user decides what to do.
- **No container/orchestrator checks.** Does not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem.
- **Cross-platform.** All checks work on macOS, Linux, and Windows (amd64 and arm64).
- **Zero Go dependencies.** stdlib only. No third-party Go modules. Git history inspection requires Git with support for `--no-lazy-fetch`.

## Install

**Homebrew (macOS):**

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
brew trust --formula astrostl/surplies/surplies
brew install surplies
```

**Go:**

```sh
go install github.com/astrostl/surplies@latest
```

**Build from source:**

```sh
make build       # local binary
make all         # all platforms: darwin/linux/windows x amd64/arm64
```

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
```

`-broad`, `-browser-cache`, and `-npm-cache` are independent opt-ins. Broad content scanning leaves both cache exclusions intact; each cache flag expands inspection only within its cache.

### Default dependency checks

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

### Default Git history checks

The scanner discovers repositories under home and additional `-root` directories, including nested repositories, bare repositories and linked worktrees. It checks blobs reachable from all locally available refs (branches, remote-tracking branches, tags and HEADs) and their history against the shared [active payload hashes](#active-payload-hashes), regardless of filename. Loose and packed objects and SHA-1/SHA-256 Git repositories are supported. A matching historical blob is reported even when the checked-out branch is clean; it does not by itself prove execution or current infection.

Dependency checks, Git history checks, and coverage details are enabled by default; no mode flags are required.

The scanner uses [Git object enumeration](https://git-scm.com/docs/git-rev-list) and [raw blob reads](https://git-scm.com/docs/git-cat-file), with replacement objects and lazy fetching disabled. It does not fetch remote refs, check out branches, run hooks, apply text conversion or content filters, or modify repositories. Repo discovery follows the normal root symlink policy; internal directory symlinks are not traversed. Repositories outside the selected roots need `-root`.

Only locally available reachable history is covered. Unfetched remote branches, missing shallow history, reflog-only/unreachable objects, uninitialized submodules and Git LFS content stored outside Git blobs are not cleared by this check. Each repository has a two-minute inspection deadline; candidate blob reads retain the exclusive 100 MB content limit. Known exact sizes avoid reading unrelated blob bodies; every candidate is verified by raw-content SHA-256. Shallow repositories produce informational `scan-limited` notices describing the available-history scope; these are not scan errors and do not change the exit status. Git absence, incompatible Git, broken refs, missing objects and command failures produce `scan-incomplete` warnings and nonzero exit status. When objects are missing, available reachable objects are still inspected, and the repository remains incomplete. Findings identify the repository, blob ID and SHA-256, with a `git log --all --find-object=<blob>` command for investigating paths/commits. Summary counts distinguish found/completed repositories, blobs considered by metadata, and candidate blobs actually hashed. Zero candidate blobs can simply mean no blob matched either known payload size.

Discovery recognizes [uv’s deliberately empty Git cache marker](https://github.com/astral-sh/uv/blob/main/crates/uv-cache/src/lib.rs) only in a versioned sdist bucket with the accompanying empty `.gitignore` and cache signature. It still searches inside that bucket for actual repositories; other invalid gitfiles remain errors.

#### Active payload hashes

The same `KnownRepoPayloadHashes` table drives filesystem and Git checks. Filesystem hash checks currently select by basename; Git checks ignore filenames. A filename or file size alone is not malicious.

| Payload | Raw-file SHA-256 | Exact bytes | Source |
|---|---|---:|---|
| keyv `Math_Symbol.js` | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | 727,680 | [Snyk keyv analysis](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/) |
| DUNE `fa-solid-400.woff2` | `11570a86f8a19cd20bc5e1df112f43c52bc939f18b51c37e902d312fd62f6d27` | 37,566 | Local DUNE incident record; exact quarantined bytes verified 2026-09-19, explicitly requested for inclusion |

DUNE's corresponding SHA-1 Git blob identity is `9b2e3a349e377ba2985c593cb3e619f84a0ea1dc`. Git object IDs include an object header and are distinct from raw-file hashes. Its provenance is the local `../battlestation/DUNE.md` record (document SHA-256 at verification: `9a71e4d42c1bda110044e44b9b8ab7a1e55ce29e7f514199cdcc00cd764d58f2`); that private incident document and the payload are not distributed with Surplies. No independent public report of this exact sample hash was found. This addition is not a new campaign or a claim of public corroboration.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan, no indicators found |
| 1 | Warning-level findings only |
| 2 | At least one critical finding |

## Scan phases

The scanner runs five phases sequentially, followed by local Git history inspection:

1. **Known malicious artifacts** — check fixed filesystem paths for dropped payloads, plus global npm and documented Electron application entrypoints and sidecars, including recursive persistence discovery under home and system roots and any `-root` directories; also warn on documented runtime/staging paths
2. **Project directory scanning** — walk home and each additional `-root` directory, inspecting every `node_modules` for compromised packages, every Composer `vendor/` for compromised packages, every `.claude/` / `.vscode/` for project-local payload files, and every build config, web font, and `.gitignore` encountered along the way for injected payload content. The same discovery walk collects Python environments and Git repositories for later phases; dependency checks select declared entrypoints and known payload candidates
3. **Python site-packages scanning** — inspect discovered `site-packages` directories plus system Python paths
4. **Network IOCs** — check active connections from `netstat -n` against known C2 IPs (and IPs resolved on-the-fly from known C2 domains)
5. **Temp directory artifacts** — check temp dirs for payload remnants
6. **Git payload hashes** — inspect blobs reachable from local refs/history against the active payload hash list

## Checks

### 1. `known-artifact` (CRITICAL)

Checks for files dropped by known supply chain attacks at specific filesystem paths. These are platform-specific RAT payloads, renamed system binaries, launcher scripts, and C2 backdoors that malware installs outside of package directories to persist after cleanup.

**What it looks for:**

| Platform | Path | Description | Source attack |
|----------|------|-------------|---------------|
| macOS | `/Library/Caches/com.apple.act.mond` | Mach-O RAT binary disguised as an Apple system daemon | axios 1.14.1/0.30.4 |
| macOS | `/tmp/6202033` | AppleScript dropper that downloads and installs the RAT | axios 1.14.1/0.30.4 |
| macOS | `~/Library/LaunchAgents/com.user.gh-token-monitor.plist` | LaunchAgent for `gh-token-monitor` persistence | mini-shai-hulud |
| macOS | `~/Library/LaunchAgents/com.user.kitty-monitor.plist` | LaunchAgent for `kitty-monitor` persistence | mini-shai-hulud (@antv wave, May 19 2026) |
| macOS/Linux | `/var/tmp/.gh_update_state` | C2 execution state file | mini-shai-hulud (@antv wave, May 19 2026) |
| Windows | `%PROGRAMDATA%\wt.exe` | PowerShell binary copied and renamed to masquerade as Windows Terminal | axios 1.14.1/0.30.4 |
| Linux | `/tmp/ld.py` | Python RAT payload | axios 1.14.1/0.30.4 |
| Linux | `~/.config/systemd/user/gh-token-monitor.service` | Systemd user service for `gh-token-monitor` persistence | mini-shai-hulud |
| Linux | `~/.config/systemd/user/kitty-monitor.service` | Systemd user service for `kitty-monitor` persistence | mini-shai-hulud (@antv wave, May 19 2026) |
| All | `~/.config/sysmon/sysmon.py` | Persistent C2 backdoor script polling for arbitrary commands | litellm 1.82.7/1.82.8 |
| All | `~/.config/systemd/user/sysmon.service` | Systemd user service for C2 persistence (restarts every 10s) | litellm 1.82.7/1.82.8 |
| All | `~/.local/bin/gh-token-monitor.sh` | Shell script that monitors and exfiltrates GitHub tokens | mini-shai-hulud |
| All | `~/.local/share/kitty/cat.py` | Python C2 daemon polling GitHub for `firedalazer` keyword commits | mini-shai-hulud (@antv wave, May 19 2026) |

**How it works:** Calls `os.Stat()` on each path. If the file exists, it's a critical finding. These paths are chosen by attackers to blend in with legitimate system files.

**Why this matters:** The axios attack's postinstall dropper downloaded a platform-specific RAT to `/Library/Caches/com.apple.act.mond` (macOS), copied `powershell.exe` to `%PROGRAMDATA%\wt.exe` (Windows), or fetched `/tmp/ld.py` (Linux). The litellm attack dropped a Python C2 backdoor to `~/.config/sysmon/sysmon.py` and registered it as a systemd user service named "System Telemetry Service" that polled `checkmarx.zone/raw` every ~50 minutes for commands to execute.

---

### 2. `phantom-dependency` (CRITICAL)

Checks for npm packages that exist solely as malware delivery vehicles and have no legitimate use. Their presence in any `node_modules` directory is always an indicator of compromise.

**Known phantom packages:**

| Package | Source attack |
|---------|---------------|
| `plain-crypto-js` | axios 1.14.1/0.30.4 |
| `@tanstack/setup` | Mini Shai-Hulud — TanStack sub-incident (May 2026) |
| `@antv/setup` | Mini Shai-Hulud — @antv wave (May 19, 2026) |
| 21 unscoped packages impersonating crypto/DeFi/AI tooling (`async-pipeline-builder`, `build-scripts-utils`, `chain-key-validator`, `crypto-credential-scanner`, `defi-env-auditor`, `defi-threat-scanner`, `deployment-key-auditor`, `dev-env-bootstrapper`, `eth-wallet-sentinel`, `llm-context-compressor`, `mnemonic-safety-check`, `model-switch-router`, `node-setup-helpers`, `project-init-tools`, `prompt-engineering-toolkit`, `solidity-deploy-guard`, `token-usage-tracker`, `wallet-backup-verifier`, `wallet-security-checker`, `web3-secrets-detector`, `workspace-config-loader`) | TrapDoor crypto stealer (May 2026) |
| 7 attacker-published Tailwind/PostCSS typosquats (`tailwind-animationbased`, `tailwind-autoanimation`, `tailwind-mainanimation`, `tailwindcss-animate-style`, `tailwindcss-style-animate`, `tailwindcss-style-modify`, `tailwindcss-typography-style`) | PolinRider (DPRK / Contagious Interview) |

**How it works:** For each `node_modules` directory found by walking the home directory, checks whether a subdirectory matching any known phantom package name exists.

**Why this matters:** The axios compromise injected `plain-crypto-js@4.2.1` as a dependency. This package was never imported by axios source code — it existed only to execute a `postinstall` hook that deployed the RAT. The attacker pre-staged a clean `4.2.0` version to establish npm account history before publishing the malicious `4.2.1`. The Mini Shai-Hulud TanStack sub-incident injected `@tanstack/setup` via an `optionalDependencies` entry pointing at a fork of the TanStack repo on GitHub — `@tanstack/setup` is not a real published `@tanstack` package and exists only to deliver the `router_init.js` payload. The May 19 @antv wave repeated the trick with `@antv/setup`, pulled from `github:antvis/G2#<imposter-orphan-commit-sha>` via the same `optionalDependencies` pattern. The TrapDoor campaign took a different approach: rather than injecting phantoms into compromised legitimate packages, all 21 npm packages are themselves purpose-built malware impersonating plausible crypto / DeFi / AI developer tooling (`eth-wallet-sentinel`, `crypto-credential-scanner`, `prompt-engineering-toolkit`, etc.) — each drops `trap-core.js` via `postinstall`, which writes `.cursorrules` and `CLAUDE.md` for AI-assistant-driven persistence and beacons to `ddjidd564.github.io` for config.

---

### 3. `compromised-version` (CRITICAL)

Checks installed npm packages against a database of known-compromised versions.

**Known compromised versions:**

| Package | Compromised versions | Attack type |
|---------|---------------------|-------------|
| `axios` | 1.14.1, 0.30.4 | RAT via phantom dependency (March 2026) |
| 100+ packages across `@uipath/*`, `@squawk/*`, `@tallyui/*`, `@beproduct/*`, `@supersurkhet/*`, `@draftauth/*`, `@draftlab/*`, `@taskflow-corp/*`, `@ml-toolkit-ts/*`, `@mesadev/*`, `@mistralai/*`, `@dirigible-ai/*`, `@opensearch-project/opensearch`, `@cap-js/*`, `@tolka/*`, and unscoped (`safe-action`, `cross-stitch`, `git-git-git`, `ts-dna`, `wot-api`, `cmux-agent-mcp`, `git-branch-selector`, `nextmove-mcp`, `agentwork-cli`, `ml-toolkit-ts`, `intercom-client`, `mbt`) | 200+ versions — see `ioc.go` and source blogs | Mini Shai-Hulud — main wave (Apr–May 2026) |
| 42 `@tanstack/*` packages (`react-router`, `router-core`, `start-plugin-core`, `react-start`, `solid-router`, `vue-router`, `router-cli`, and the rest of the router/start surface) | 84 versions — two per package per the "double-tap" pattern | Mini Shai-Hulud — TanStack sub-incident, pwn-request → Actions cache poisoning → OIDC token theft (May 11, 2026) |
| 317 packages across `@antv/*` (the AntV visualization framework — 279 packages including `@antv/g2`, `@antv/g6`, `@antv/l7`, `@antv/x6`, `@antv/s2`, `@antv/f2`, `@antv/graphin`, and the rest of the visualization surface), `@lint-md/*`, and unscoped AntV-adjacent packages (`echarts-for-react`, `timeago.js`, `size-sensor`, `jest-canvas-mock`, `canvas-nest.js`, `ribbon.js`, and 30 more by the same maintainer) | 600+ versions — two-to-three per package per the "double-tap" pattern | Mini Shai-Hulud — @antv wave, AntV maintainer compromise (May 19, 2026) |
| 31 packages across `@redhat-cloud-services/*` (`chrome`, `rbac-client`, `host-inventory-client`, the `frontend-components-*` family, the various `*-client` SDKs, and the `hcc-*-mcp` servers) | 31 versions — one per package | Mini Shai-Hulud — Red Hat Cloud Services wave, GitHub Actions OIDC token theft from `RedHatInsights/javascript-clients` (June 1, 2026) |
| 11 packages: `keyv`, `@cacheable/net`, `@cacheable/node-cache`, `@cacheable/memory`, `@cacheable/utils`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, `ecto` | 11 versions — one per package (`keyv@6.0.0`, `@cacheable/net@2.1.1`, `@cacheable/node-cache@3.1.2`, `@cacheable/memory@2.2.1`, `@cacheable/utils@2.5.1`, `cacheable@2.5.1`, `flat-cache@6.1.24`, `cacheable-request@13.0.20`, `file-entry-cache@11.1.6`, `cache-manager@7.2.10`, `ecto@5.0.1`) | keyv npm compromise — compromised release path for maintainer `jaredwray` (August 4, 2026) |
| 38 compromised legitimate packages whose maintainers were infected, including `fetch-page-assets`, `html-to-gutenberg`, `itsa-react-docviewer`, `@joyfill/*`, `@testrelic/*`, `@common-stack/generate-plugin`, `@vite-*/*`, `@im_ahsan/chatbot-widget`, `bianira-ui`, `fluid-type-ui`, and the `tailwind-*` / `tailwindcss-*` plugin family | 100+ versions. `fetch-page-assets` is the notable one: only `1.2.9` was ever pulled (GHSA-vxq2-vhm7-7mhq), while `1.2.10`–`1.2.14` remained live and unflagged as `latest`. Pin to `<= 1.2.8`. npm's `0.0.1-security` takedown placeholders are deliberately excluded | PolinRider (DPRK / Contagious Interview) |

**How it works:** For each installed package, reads its manifest once for both known-version matching and lifecycle analysis. Selected read/parse failures report incomplete coverage.

**Why this matters:** These versions were published to npm by either compromised maintainer accounts or maintainers acting maliciously. Lock files and caches can pin you to a bad version long after it's been unpublished from the registry.

---

### 4. `suspicious-install-script` (WARN)

Scans project and installed-package `package.json` files for `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepack`, and `postpack` lifecycle scripts that contain patterns commonly used by malware. (`prepare` is included because the Mini Shai-Hulud TanStack sub-incident used `"prepare": "bun run tanstack_runner.js && exit 1"`; npm runs `prepare` on local installs and on `npm pack`, so it's a viable malware vehicle.)

**Flagged patterns:**

| Pattern | Flag | Why it's suspicious |
|---------|------|-------------------|
| `curl ` | `downloads-via-curl` | Fetches external payloads at install time |
| `wget ` | `downloads-via-wget` | Fetches external payloads at install time |
| `powershell` | `uses-powershell` | Shell execution on Windows |
| `-ExecutionPolicy Bypass` | `bypasses-execution-policy` | Disables PowerShell security policy |
| `eval(` or `eval ` | `uses-eval` | Dynamic code execution |
| `base64` | `uses-base64` | Encoded payloads |
| `\x` | `hex-encoded-strings` | Obfuscated strings |
| `nohup ` | `background-process` | Detaches payload from npm process tree |
| `> /dev/null` | `suppresses-output` | Hides command output |
| `-WindowStyle Hidden` | `hidden-window` | Invisible PowerShell window |
| `.vbs` | `uses-vbscript` | VBScript dropper (Windows) |
| `osascript` | `uses-applescript` | AppleScript execution (macOS) |

**How it works:** Reads encountered project manifests and installed package manifests (including scoped packages under `@org/`) with shared size/time limits and parse-error reporting. Checks each lifecycle script against the pattern list. Reports the script content (truncated to 80 chars) and all matched flags. The exact standard Yarn `preinstall` command is exempt from these string heuristics only when both the package directory name and manifest name are `yarn`; other hooks and modified commands remain checked. Its referenced JavaScript is still inspected for obfuscation. See [Yarn’s release manifest generator](https://github.com/yarnpkg/yarn/blob/v1.22.22/scripts/update-dist-manifest.js).

**Why this matters:** The axios attack used a `postinstall` hook in `plain-crypto-js` to run `node setup.js`, which then used `curl`/`powershell`/`osascript` to download and execute RAT payloads. Legitimate packages rarely need to download executables or run shell commands during install.

---

### 5. `obfuscated-install-script` (WARN)

When a lifecycle script references a JavaScript file (e.g., `node setup.js`), reads that file and checks for obfuscation techniques used to hide malicious intent from code review and static analysis.

**Obfuscation signals:**

| Signal | Threshold | Description |
|--------|-----------|-------------|
| `heavy-hex-escapes` | > 20 `\x` sequences | Strings encoded as hex escape sequences to avoid keyword detection |
| `xor-operations` | > 10 `^` operators in files < 10 KB | XOR cipher used to decrypt strings at runtime |
| `heavy-base64-usage` | > 3 combined `base64`/`atob(`/`Buffer.from(` | Multiple layers of base64 encoding |
| `dynamic-code-execution` | any `eval(` or `Function(` | Runtime code generation from strings |
| `excessive-string-concat` | > 15 `'+'` or `"+"` patterns | Building up module names or URLs char-by-char to avoid static detection |
| `self-deletion` | any `unlink(__filename` or `unlink(__dirname` | File deletes itself after execution to destroy evidence |

**How it works:** Inspects supported JS/CJS/MJS-family targets directly referenced by lifecycle scripts with bounded reads. Reports these generic patterns as warnings; known payload signatures are checked independently. General source inspection runs separately over eligible traversed files.

**Why this matters:** The axios dropper `setup.js` was 4.2 KB of obfuscated JavaScript using XOR cipher with the key `"OrDeR_7077"` plus base64 decoding to hide C2 URLs, module names, and shell commands. It also deleted itself via `fs.unlink(__filename)` after execution. These patterns are unusual in legitimate install scripts.

---

### 6. `npm-payload-file` (CRITICAL)

Checks for known malicious filenames inside packages of a specific npm scope, independent of the package's declared version. Catches leftover payload artifacts after partial cleanup or version-string tampering.

**Known npm payload files:**

| Scope / package | Filename | Description | Source attack |
|-----------------|----------|-------------|---------------|
| `@tanstack/*` | `router_init.js` | ~2.3 MB obfuscated JS payload delivered via the pwn-request → Actions cache poisoning vector | Mini Shai-Hulud — TanStack sub-incident (May 2026) |
| `@tanstack/*` | `tanstack_runner.js` | Bun-loaded runner invoked from the malicious `prepare` lifecycle hook (SHA-256 `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`) | Mini Shai-Hulud — TanStack sub-incident (May 2026) |
| `@cacheable/*`, `keyv`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, `ecto` | `setup.mjs` | Preinstall loader (29,918 bytes; SHA-256 `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`) invoked via `"preinstall": "node setup.mjs"` | keyv npm compromise (Aug 2026) |
| `@cacheable/*`, `keyv`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, `ecto` | `Math_Symbol.js` | Second-stage payload (727,680 bytes; SHA-256 `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`), byte-identical across all 11 malicious releases | keyv npm compromise (Aug 2026) |

**How it works:** While walking each `node_modules` directory, for every package under a tracked scope (or matching an unscoped package name key), `os.Stat()` is called on each known payload filename inside the package directory. Presence alone is the signal — no content inspection is performed.

**Why this matters:** The Mini Shai-Hulud TanStack sub-incident published 84 malicious versions across 42 `@tanstack/*` packages, dropping both `router_init.js` (the obfuscated payload) and `tanstack_runner.js` (the Bun loader invoked from the `prepare` hook). The keyv npm compromise dropped the same `setup.mjs` / `Math_Symbol.js` pair into all 11 affected tarballs (including high-reach transitive deps like `flat-cache` and `file-entry-cache` via ESLint toolchains). Cleaning up by downgrading to a "clean" version doesn't necessarily remove the payload file from disk if installs are layered, and lock files / caches can resurrect compromised tarballs. Matching on the payload filename rather than the version number catches both scenarios.

---

### 7. `compromised-python-version` (CRITICAL)

Checks installed Python packages against a database of known-compromised versions by scanning `.dist-info` directories in every `site-packages` found.

**Known compromised versions:**

| Package | Compromised versions | Attack type |
|---------|---------------------|-------------|
| `litellm` | 1.82.7, 1.82.8 | Credential stealer + C2 backdoor (2026) |
| `guardrails-ai` | 0.10.1 | Mini Shai-Hulud PyPI artifact (May 2026) |
| `lightning` | 2.6.2, 2.6.3 | Mini Shai-Hulud PyPI artifact (May 2026) |
| `mistralai` | 2.4.6 | Mini Shai-Hulud PyPI artifact (May 2026) |
| `pybitjs` | 0.1.0 | PolinRider PyPI artifact — published by an infected maintainer |
| `pyservercheck` | 0.1.1 | PolinRider PyPI artifact — published by an infected maintainer |

**How it works:** Walks the home directory for `site-packages` directories (virtualenvs, `.local`, etc.) and also checks well-known system Python paths:
- Unix: `/usr/lib/python3.*/site-packages`, `/usr/local/lib/python3.*/site-packages`, `/opt/homebrew/lib/python3.*/site-packages`
- Windows: `%LOCALAPPDATA%\Programs\Python\Python3*\Lib\site-packages`, `C:\Python3*\Lib\site-packages`, `C:\Program Files\Python3*\Lib\site-packages`

For each `site-packages`, parses `.dist-info` directory names to extract package name and version. Package names are normalized (underscores to hyphens, lowercased) to match PyPI conventions.

**Why this matters:** litellm 1.82.8 placed a malicious `.pth` file in site-packages for interpreter-level persistence. litellm 1.82.7 embedded a base64-encoded payload directly in `litellm/proxy/proxy_server.py`, triggered on proxy module import. Both versions harvested credentials (SSH keys, AWS/GCP/Azure creds, `.env` files, shell history, crypto wallets), encrypted them with AES-256-CBC + RSA-4096, and exfiltrated them to `models.litellm.cloud`. A C2 backdoor was installed via systemd for ongoing access. Lock files and cached wheels can keep compromised versions installed indefinitely.

---

### 8. `malicious-pth-file` (CRITICAL)

Checks for known malicious `.pth` files in Python `site-packages` directories.

**Known malicious .pth files:**

| Filename | Source attack |
|----------|---------------|
| `litellm_init.pth` | litellm 1.82.8 |

**How it works:** Scans every `site-packages` directory for `.pth` files matching known malicious filenames.

**Why this matters:** Python's site module automatically executes code in `.pth` files on every interpreter startup. The litellm 1.82.8 attack placed `litellm_init.pth` (34,628 bytes) in `site-packages`, which meant the credential-stealing payload ran not just on `pip install`, but on **every subsequent Python invocation** — including unrelated scripts, Jupyter notebooks, and CI/CD jobs. This is a particularly dangerous persistence mechanism because it doesn't require importing the compromised package.

---

### 9. `suspicious-pth-file` (WARN)

Heuristic check for unknown `.pth` files in `site-packages` with content patterns associated with malware.

**Flagged patterns:**

| Pattern | Flag |
|---------|------|
| `subprocess` | `uses-subprocess` |
| `base64` | `uses-base64` |
| `exec(` | `uses-exec` |
| `eval(` | `uses-eval` |
| `compile(` | `uses-compile` |
| `os.system` | `uses-os-system` |
| `urllib` | `uses-urllib` |
| `requests` | `uses-requests` |
| `socket` | `uses-socket` |
| `\x` | `hex-encoded-strings` |
| `/bin/sh` or `/bin/bash` | `shell-execution` |
| `powershell` | `uses-powershell` |
| (file > 5 KB) | `unusually-large` |

**How it works:** Reads `.pth` file content and checks against the pattern list. Only reports when **two or more** flags match, to avoid false positives from legitimate `.pth` files (e.g., `coloredlogs.pth` and `coverage.pth` use `exec` for simple env-var-gated imports).

**Why this matters:** Legitimate `.pth` files are typically a few lines containing import paths. The litellm `.pth` file was 34 KB of encoded payload — orders of magnitude larger and more complex than any legitimate use. Multiple suspicious patterns in a single `.pth` file strongly suggest malicious intent.

---

### 10. `compromised-composer-version` (CRITICAL)

Checks installed Composer (PHP/Packagist) packages against a database of known-compromised versions by reading `vendor/composer/installed.json` in every Composer vendor directory found under the home directory.

**Known compromised versions:**

| Package | Compromised versions | Attack type |
|---------|---------------------|-------------|
| `intercom/intercom-php` | 5.0.2 | Mini Shai-Hulud Composer artifact (May 2026) |
| 19 packages: `sevenspan/laravel-chat`, `sevenspan/code-generator`, `sevenspan/laravel-whatsapp`, `roberts/leads`, `visanduma/nova-two-factor`, `visanduma/laravel-hrm`, `visanduma/laravel-invoice`, `visanduma/laravel-auth-switch`, `visanduma/nova-back-navigation`, `plusinfolab/logstation`, `thiio/kubernetes-php-sdk`, `olc/olc-php`, `adxio/twig-hmvc`, `arsl/optima-class`, `lambda-platform/moqup`, `imfaisii/twitter-api-v2-php`, `mahbub/laravel-saas-kit`, `mahbubur508/api-auth`, `henrique-borba/php-sieve-manager` | 61 artifacts — mostly `dev-*` branch refs rather than tagged releases | PolinRider (DPRK / Contagious Interview) |

**How it works:** During the home-directory walk, any `vendor/` directory that contains a `composer/installed.json` is identified as a Composer install. The scanner parses both Composer 1.x (flat array) and 2.x (`{packages: [...]}`) envelope formats, then compares each installed package against the known-bad list. A leading `v` on either the installed or known-bad version string is stripped so `v5.0.2` and `5.0.2` both match.

**Why this matters:** The Mini Shai-Hulud worm's reach extended beyond npm into PyPI and Composer/Packagist. Detection here mirrors the npm and Python version checks for cross-ecosystem coverage of the same campaign.

PolinRider hits Packagist harder than it hits npm, and for a structural reason worth understanding: it propagates through maintainer machines rather than through the registry. The worm finds local git repos, injects its loader into a JS config file, amends the last commit and force-pushes — and Packagist then picks up the poisoned commit on *every tracked branch*. That is why most entries are `dev-*` branch refs (the version string in `installed.json` is literally `dev-main`) rather than semver tags. One entry, `olc/olc-php` at `dev-fix/remove-malware`, is not a typo: the branch a maintainer opened to clean up was itself re-poisoned before Packagist indexed it.

---

### 11. `network-ioc-active-connection` (CRITICAL)

Checks active network connections for known command-and-control domains and IP addresses from documented supply chain attacks.

**Known C2 indicators:**

| Indicator | Type | Source attack |
|-----------|------|---------------|
| `sfrclak.com` | Domain | axios — primary C2 (port 8000) |
| `142.11.206.73` | IP | axios — C2 server IP |
| `models.litellm.cloud` | Domain | litellm — credential exfiltration (mimics litellm.ai) |
| `checkmarx.zone` | Domain | litellm — C2 polling (mimics Checkmarx security brand) |
| `api.masscan.cloud` | Domain | mini-shai-hulud — direct POST exfiltration |
| `git-tanstack.com` | Domain | mini-shai-hulud — marker/staging domain |
| `filev2.getsession.org` | Domain | mini-shai-hulud — Session messenger CDN abused for exfil |
| `seed1.getsession.org` | Domain | mini-shai-hulud — Session seed used for TLS pinning |
| `seed2.getsession.org` | Domain | mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel |
| `seed3.getsession.org` | Domain | mini-shai-hulud (TanStack sub-incident) — Session seed for exfil channel |
| `litter.catbox.moe` | Domain | mini-shai-hulud (TanStack sub-incident) — secondary payload host (legit pastebin service abused) |
| `t.m-kosche.com` | Domain | mini-shai-hulud (@antv wave) — RSA+AES exfil disguised as OpenTelemetry traces (`/api/public/otel/v1/traces`) |
| `193.247.144.38`, `166.88.73.46`, `166.88.134.62`, `23.27.13.135` | IP | PolinRider — C2 hosts observed in the Packagist wave (all AS149440 / Evoxt) |
| `166.88.54.158`, `198.105.127.210`, `23.27.202.27`, `154.91.0.103`, `136.0.9.8`, `166.88.4.2`, `23.27.120.142`, `202.155.8.173`, `166.88.134.82`, `188.43.33.249`, `23.27.13.43` | IP | PolinRider — interim firewall-block list from OSM's remediation guide |

**A note on the PolinRider IPs:** they are a snapshot, not a list, and a miss here means nothing. That campaign resolves its C2 off the Ethereum blockchain — the NullReceiver technique encodes an IPv4 address in the destination-address bytes of a zero-value transaction from a known wallet, tailed with the ASCII marker `helloipbot!!`. There is no domain, registrar, certificate or host to seize, and publishing the next address costs the operator about one transaction's worth of gas, so the addresses rotate on their whim.

The Ethereum JSON-RPC endpoints the loader queries (`1rpc.io`, `eth.drpc.org`, `ethereum-rpc.publicnode.com`, `eth-mainnet.public.blastapi.io`, `eth.blockscout.com`) are deliberately **not** listed as C2 domains. They are legitimate public infrastructure, and flagging them would report every web3 developer on the machine as compromised. Egress to them from a host that has no business speaking JSON-RPC is the durable signal in this campaign, but it is one for network monitoring to act on, not for a filesystem scanner's connection check.

**How it works:** Runs `netstat -n` and resolves the existing C2 domain list under a five-second deadline. Parses established TCP remote endpoints in macOS, Linux and Windows formats; IP matching is exact, including IPv4-mapped IPv6 normalization. Collection failures, timeouts and malformed TCP rows report incomplete coverage. DNS NXDOMAIN and successful-but-filtered/empty answers produce distinct scope notices. No C2 service is contacted.

**Why this matters:** The axios RAT and litellm C2 backdoor both beacon out programmatically — these connections won't appear in shell history. Catching an active connection to `sfrclak.com:8000` or `checkmarx.zone` at scan time is a direct indicator of a running implant.

---

### 12. `suspicious-temp-file` (WARN)

Checks system temp directories for files matching patterns associated with supply chain attack payloads.

**Directories checked:**

- `os.TempDir()` (platform default)
- `/tmp` (Linux/macOS)
- `/var/tmp` (Linux/macOS)

**Patterns:**

| Pattern | Description | Source attack |
|---------|-------------|---------------|
| `*.vbs` | VBScript dropper — axios stages `%TEMP%\{campaignID}.vbs` on Windows | axios 1.14.1/0.30.4 |
| `*.ps1` | PowerShell payload — axios stages `%TEMP%\{campaignID}.ps1` on Windows | axios 1.14.1/0.30.4 |
| `.pg_state` | C2 state tracking file (last-downloaded URL) | litellm 1.82.7/1.82.8 |
| `pglog` | Downloaded payload staging directory | litellm 1.82.7/1.82.8 |
| `tpcp.tar.gz` | AES-256+RSA-4096 encrypted credential exfiltration archive | litellm 1.82.7/1.82.8 |
| `tmp.0987654321.lock` | Bun loader execution lock file | mini-shai-hulud (Red Hat Cloud Services wave, June 1 2026) |
| `b-*/b.zip` | Bun loader staged payload archive, extracted under `/tmp/b-*` | mini-shai-hulud (Red Hat Cloud Services wave, June 1 2026) |

**How it works:** Uses `filepath.Glob` to match patterns in each temp directory. Deduplicates directories (e.g., if `os.TempDir()` returns `/tmp`).

**Why this matters:** Temp directories are common staging grounds for supply chain payloads because they're writable without elevated privileges and often excluded from security monitoring. The axios attack staged a VBScript dropper (`%TEMP%\{campaignID}.vbs`) and a PowerShell payload (`%TEMP%\{campaignID}.ps1`) on Windows; both are self-deleting. The litellm attack used `/tmp/.pg_state` to track which C2 commands had been executed, `/tmp/pglog` for downloaded binaries, and assembled stolen credentials into `/tmp/tpcp.tar.gz` before exfiltration.

---

### 13. `project-artifact` (CRITICAL)

Checks for malicious files dropped inside project-local config directories (`.claude/`, `.vscode/`) by supply chain attacks. Unlike `known-artifact`, which checks fixed home-relative or system paths, this check runs against every project under the home directory: any `.claude/` or `.vscode/` directory encountered during the walk is inspected for a specific malicious filename.

**Known project-local artifacts:**

| Config dir | Filename | Description | Source attack |
|------------|----------|-------------|---------------|
| `.claude/` | `router_runtime.js` | Bun payload loaded via a `SessionStart` hook injected into `.claude/settings.json` | mini-shai-hulud |
| `.claude/` | `execution.js` | Bun payload — alternate filename for the same campaign payload | mini-shai-hulud |
| `.claude/` | `setup.mjs` | Shared setup module used by the Claude Code and VS Code droppers | mini-shai-hulud; keyv npm compromise (Aug 2026) |
| `.claude/` | `index.js` | Bun payload copy committed into repos as the AntV wave's persistence vehicle | mini-shai-hulud (@antv wave, May 19 2026) |
| `.claude/` | `math_init.js` | Second-stage payload name used in the Claude Code SessionStart hook path (npm tarballs ship the same stage as `Math_Symbol.js`) | keyv npm compromise (Aug 2026) |
| `.vscode/` | `execution.js` | Bun payload — alternate filename for the same campaign payload | mini-shai-hulud |
| `.vscode/` | `setup.mjs` | Shared setup module loaded via a `folderOpen` task injected into `.vscode/tasks.json` | mini-shai-hulud; keyv npm compromise (Aug 2026) |

**How it works:** The home-directory walk (the same one used for `node_modules`) returns `SkipDir` when it encounters a `.claude/` or `.vscode/` directory after running `os.Stat()` on each known malicious filename inside. The named artifact checks use presence alone. The same-directory content scan also reads `tasks.json` for payload signatures and automatic Node-to-font execution; deep mode descends into nested files.

**Why this matters:** The Mini Shai-Hulud worm modifies project-local config to ensure the payload runs the next time a developer opens that project. Editing `.claude/settings.json` with a `SessionStart` hook makes the next `claude` invocation in that repo execute `.claude/router_runtime.js`; editing `.vscode/tasks.json` with a `folderOpen` task makes the next VS Code window opened in that repo execute `.vscode/setup.mjs`. The keyv npm compromise used the same IDE-hook pattern, committing `.claude/setup.mjs`, `.claude/math_init.js`, and `.vscode/setup.mjs` into the keyv repository (verified `github-actions[bot]` commit) so that opening the project in Claude Code or VS Code re-triggers the loader even without an npm install. The malicious files survive `git clean` against most ignore lists, persist across `node_modules` reinstalls, and re-trigger exfiltration on every developer session — finding the payload file is often the only reliable signal that a project was touched, since the lifecycle hook itself is short and easy to miss in a diff.

---

### 14. `phantom-python-package` (CRITICAL)

The PyPI counterpart to `phantom-dependency`. Checks for PyPI distribution names that exist solely as malware delivery vehicles and have no legitimate use. Their presence in any `site-packages` — in any version — is always an indicator of compromise.

**Known phantom Python packages:**

| Package | Source attack |
|---------|---------------|
| `cryptowallet-safety` | TrapDoor crypto stealer (May 2026) |
| `data-pipeline-check` | TrapDoor crypto stealer (May 2026) |
| `defi-risk-scanner` | TrapDoor crypto stealer (May 2026) |
| `env-loader-cli` | TrapDoor crypto stealer (May 2026) |
| `eth-security-auditor` | TrapDoor crypto stealer (May 2026) |
| `git-config-sync` | TrapDoor crypto stealer (May 2026) |
| `solidity-build-guard` | TrapDoor crypto stealer (May 2026) |

**How it works:** While scanning each `site-packages`, the existing `.dist-info` parser pulls the package name (normalized: lowercased, underscores converted to hyphens) and matches it against the phantom list. Match on name alone — the installed version is reported but not used as part of the decision, since every release of these packages is malicious.

**Why this matters:** Unlike compromised legitimate packages (where downgrading to a pre-incident version restores safety), phantom packages have no clean version — every release is malware. The TrapDoor campaign published 7 such PyPI packages impersonating crypto / DeFi / data-pipeline tooling, all from GitHub actor `ddjidd564`. The earliest observed upload was `eth-security-auditor@0.1.0` on May 22, 2026; matching on name lets the check stay valid as the attacker republishes under new versions.

---

### 15. `fake-font-payload` (CRITICAL)

Checks whether a file named like a web font actually contains font data. A `.woff2`, `.woff`, `.ttf`, or `.otf` whose bytes are text rather than a font container is a JavaScript loader wearing an asset's name.

**How it works:** Reads the first bytes of each font-extension file found during the project walk and compares them against the magic numbers for every font container format (`wOF2`, `wOFF`, `OTTO`, `ttcf`, `true`, `typ1`, the TrueType `00 01 00 00` header, and the Type 1 variants). If none match, the file is sampled for text: any NUL byte means binary, and at least 95% of the first 512 bytes must be printable ASCII or whitespace. HTML and XML documents are excluded — a site mirrored with `wget`, or a single-page app behind a catch-all route, saves the index page under a missing asset's name, which is genuinely not font data and genuinely not an indicator of anything.

**Why this matters:** This is the check that survives the campaign rotating its constants. PolinRider hides its loader inside `public/fonts/fa-solid-400.woff2` specifically because a `.woff2` reads as binary: reviewers skip it, `grep`-for-IOCs passes report it clean, and diff tools show it as an opaque blob. But whatever generation of the payload is inside, and whatever string constants it uses, the file still has to be JavaScript for `node` to run it — so the extension/content mismatch holds even when every signature in the list below has been rotated out from under us. It is also the cheapest possible check: the first four bytes settle it.

---

### 16. `payload-signature` (CRITICAL)

Checks selected metadata, execution targets and documented injection candidates for published payload indicators. Project membership and source extensions alone do not select file contents. `-broad` expands general content inspection outside projects; `-browser-cache` separately includes browser caches; it is not enabled by default. Dependency content inspection uses the default selection policy described above.

**Known signatures:**

| Signature | Description | Source attack |
|-----------|-------------|---------------|
| `("rmcej%otb%",2857687)` (matched as `rmcej%otb%`) | Loader signature, original March 2026 variant | PolinRider |
| `_$_1e42` | Decoder function name, original March 2026 variant | PolinRider |
| `Cot%3t=shtP` | Loader signature, rotated April 2026 variant | PolinRider |
| `global['!']=` | Global injection marker | PolinRider |
| `global['_V']=` | Global injection marker, rotated April 2026 variant | PolinRider |
| `global.i="A8-` | Campaign-tag marker (fake-font and `babel.config.cjs` variants) | PolinRider |
| `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` (and the EIP-55 checksummed spelling) | NullReceiver C2-resolver wallet — the address the loader reads its next C2 host from | PolinRider |
| `/0x/cls` | NullReceiver second-stage fetch path (XOR-encrypted payload) | PolinRider |
| `/0x/ls` | NullReceiver second-stage fetch path (XOR-encrypted payload) | PolinRider |
| `/*RS260605*/`, `/*C250617A*/`, `/*C250618A*/`, `/*C250619A*/`, `/*C250620A*/`, `/*C260511A*/`, `/*C260512A*/` | Exact application-persistence markers from Socket and StepSecurity's Joyfill analysis | PolinRider (DPRK / Contagious Interview) |
| `__inzCR`, `/*M260630A*/` | Exact application-loader markers corroborated by ByteGuard | PolinRider (DPRK / Contagious Interview) |
| `q4FZkxX{!h,Sr3=@`, `y-p_>d$0B&@^1aQk`, `ThZG+0jfXE6VAGOJ` | Published cls, ls, and boot-stage XOR keys | PolinRider (DPRK / Contagious Interview) |
| `X-Payload-B64` (case-insensitive) | Payload response-header name from Amazon Inspector advisories | PolinRider (DPRK / Contagious Interview) |
| `/0x/clb`, `/0x/js`, `/$/boot`, `/verify-human/`, `helloipbot!!` (also hex `68656c6c6f6970626f742121`) | Published stage paths and dead-drop recipient marker | PolinRider (DPRK / Contagious Interview) |
| `/u/f` together with `socket.io-client` | Upload endpoint with RAT client context; neither string alone triggers this rule | PolinRider (DPRK / Contagious Interview) |

**How it works:** Published literal signatures also match fixed-width ASCII `\xNN` / `\uNNNN` escapes without evaluating code. Header names and the existing resolver wallet are case-insensitive. For selected candidates (or with `-broad` outside dependencies), supported formats include ordinary JS/CJS/MJS/TS/JSX/TSX, Python, shell, JSON/JSONC settings, YAML/TOML/INI/conf, XML/plist/service, HTML/Vue/Svelte, PHP/Ruby/Dart, text/Markdown, extensionless files, and supported assets; the exact list is `SignatureScannedExtensions` in `ioc.go`. Other extensions remain excluded. General source candidates receive an 8 KiB prefix check before their bodies are read; a NUL or invalid UTF-8 prefix excludes the binary body from text inspection. A UTF-8 character split by the prefix boundary is allowed. Binary/non-UTF-8 content is not searched as general source. Known markers in documentation/test paths produce warnings rather than confirmed-compromise claims; this is not a repository-controlled suppression mechanism. Text candidates below 100 MB are still read in full within a shared five-second read/inspection deadline. Larger inputs and failures produce coverage diagnostics. Recognized asset headers only receive header inspection; archives are not unpacked.

**Why this matters:** PolinRider appends its loader to the end of a real build config after roughly 280 spaces of padding. The file still opens, still builds, and still looks untouched in a diff unless you scroll right — a `tailwind.config.js` that is normally 80–200 bytes becomes ~5,000. Filename matching cannot find this, because the file is supposed to exist and is supposed to have that name. Content matching is the only option. Note that the campaign has already rotated its constants once (the March `rmcej%otb%` / `_$_1e42` pair became `Cot%3t=shtP` / `MDy` in April, an evasion response to OSM's published YARA rule), which is why every generation is listed and why a clean result here is not proof of anything — see the next check.

The wallet and initial fetch-path signatures identify the resolver rather than an obfuscator generation. The markers above identify a *generation of the obfuscator*; the wallet address and the `/0x/…` fetch paths identify the *C2 resolver itself*, which is the part the campaign cannot cheaply change. Every address in the C2 IP list rotates for the price of one Ethereum transaction, because the loader reads the next host off-chain — but the wallet it reads **from** is compiled into the payload, so moving it means republishing to every victim. That makes it the one constant that pins a sample to this campaign rather than to a guess. Two caveats, both real: `bianira-ui` writes identifiers as `\uXXXX` escapes; the scanner now normalizes fixed-width ASCII escapes as well as checking its version pin, and the OSV records that document these constants describe delivery through trojanized npm packages, not the force-pushed repositories the rest of the PolinRider coverage targets. Same resolver and same C2 family, different distribution.

---

### 17. `padded-source-file` (WARN)

Flags a JS-family file, dictionary file, or font-extension file whose contents are text and which contains 200 or more consecutive spaces between non-whitespace text on the same line.

**How it works:** Search for a precomputed space run, then check each matching line with leading and trailing whitespace removed. Applied only to files that already passed the signature scan without matching. If a known signature matched, this check stays quiet — one injection produces one finding, not two.

The text precondition is load-bearing, not a nicety. Pushing a payload off the right edge of an editor viewport is a trick that only means anything in a file a human reads as text; inside a binary container, a run of `0x20` bytes is just data. A 21 MB CJK TrueType font has ample room to contain 200 consecutive spaces in its glyph tables by coincidence, and flagging that is noise. Fonts that really are text are still caught — as a critical `fake-font-payload` finding, by the magic-number check above.

**Why this matters:** This is the deliberate backstop for `payload-signature`. The check requires 200+ spaces between non-whitespace text on the same line, matching the documented off-screen append pattern. Leading indentation and trailing whitespace do not qualify; generated license comments can contain hundreds of leading spaces. Because it describes the *shape* of the injection rather than any particular payload, it keeps working after the campaign rotates its constants — which it has done once already and will do again. It is a warning rather than a critical finding because the shape alone is not proof, and the honest reading of a hit here is "this looks like an injection we do not have a signature for yet."

---

### 18. `malicious-repo-artifact` (CRITICAL)

Checks for known artifact filenames during the home-directory walk rather than at a fixed path. Ambiguous filenames require content verification.

**Known artifacts:**

| Filename | Description | Source attack |
|----------|-------------|---------------|
| `temp_auto_push.bat` | Propagation script: resets the clock, amends the last commit, force-pushes | PolinRider |
| `config.bat` | Hidden orchestrator (added to `.gitignore` to hide it from `git status`) | PolinRider |
| `*.inz.cjs`, `*.inz.orig` | Implant module dropped beside a patched Electron or npm entrypoint | PolinRider |
| `router_init.js` | Payload loader | Mini Shai-Hulud |
| `tanstack_runner.js` | Bun-loaded payload | Mini Shai-Hulud |
| `Math_Symbol.js` | Second-stage payload, confirmed by SHA-256 `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | keyv npm compromise |
| `fa-solid-400.woff2` | Exact dropper bytes, confirmed by SHA-256 in the active hash list | PolinRider (DUNE incident-specific IOC) |

**How it works:** Exact basename match for the named files except the SHA-256-confirmed `Math_Symbol.js` and `fa-solid-400.woff2`; suffix match for the `.inz` modules, because the stem varies with whichever file was patched. A legitimate `build.bat` is not flagged.

`Math_Symbol.js` is also a [legitimate Unicode data filename](https://github.com/mathiasbynens/regenerate-unicode-properties/blob/v10.2.0/General_Category/Math_Symbol.js). Its name selects it for bounded content inspection; this check only reports it when its bytes match the known malicious SHA-256. The file is also checked for other payload signatures and padding. Neither its path nor its size alone establishes compromise. Read failures follow the normal incomplete-scan reporting. This check also runs inside dependency directories by default.

`router_init.js`, `tanstack_runner.js` and `Math_Symbol.js` also appear in the package-scoped `npm-payload-file` check, which remains unchanged and can flag unexpected payload files in known affected packages. The repository checks additionally cover other carriers encountered during the walk. `setup.mjs` stays package-scoped because it is a plausible legitimate filename.

**Why this matters:** `temp_auto_push.bat` is the highest-confidence indicator of past compromise in the entire campaign. PolinRider's propagation runs locally, not from a server: the script resets the machine clock, amends the last commit so the timestamp matches the one it replaced, and force-pushes using whatever git credentials are already cached. Nothing leaves the machine that GitHub can distinguish from the real developer — same device, same SSH key, same behavior GitHub sees every day — which is exactly why the artifact left on disk is the evidence. OSM found it still sitting in 101 victim repositories whose owners had already cleaned the payload out of their config files and believed they were done.

---

### 19. `gitignore-injection` (CRITICAL)

Checks `.gitignore` files for entries an attack added to conceal a file it dropped.

**Known injected entries:**

| Entry | Description | Source attack |
|-------|-------------|---------------|
| `config.bat` | Hides the dropped orchestrator from `git status` | PolinRider |

**How it works:** Reads each `.gitignore` found during the walk and compares every trimmed line against the known-injected list as a whole-line match.

**Why this matters:** This one survives cleanup of the file it was hiding. A developer who finds and deletes `config.bat` has removed the payload but not the evidence that something put it there — and the `.gitignore` line is what kept `git status` quiet while the orchestrator sat in the repo. A `.gitignore` listing a file the developer never created is a deliberate concealment step, and it is worth knowing about even after the file itself is gone.

---

### 20. `patched-npm-cli` (CRITICAL)

Checks the global npm CLI entrypoint (`npm/lib/cli.js`) for signs of having been overwritten.

**How it works:** Glob-matches every install layout surplies supports — system (`/usr/lib`, `/usr/local/lib`), Homebrew (`/opt/homebrew`), MacPorts (`/opt/local`), nvm, fnm, Volta, `n`, `.npm-global`, and the Windows `%APPDATA%\npm` and `%ProgramFiles%\nodejs` paths. Globs rather than `npm root -g` on purpose: multiple Node installs routinely coexist, and asking one of them where it lives reports on that one only. A file over 100 KiB is flagged on size; under that, it is still read and checked against the `payload-signature` list and `.inz.cjs` / `.inz.orig` references, so a small sidecar-loading stub is caught too. Adjacent sidecar files are checked by name, including when the CLI entrypoint has been removed.

**Why this matters:** This is the persistence that outlasts everything else. A poisoned project config only runs when that project builds; a patched `cli.js` re-spawns the payload on *every* `npm`, `npx`, or `npm exec` invocation, survives a reboot, and survives a full credential rotation — one developer traced their reinfection to an editor silently running `npm exec <package>@latest` in the background. The real file is a few hundred bytes across every npm major version (four lines that require the implementation); the PolinRider replacement is roughly 1 MB with the payload appended after a long whitespace run starting on line 5. The 100 KiB threshold sits two orders of magnitude above normal and an order below the malicious size, so the check does not depend on either number staying exact.

---

### 21. `scan-incomplete` (WARN)

Reports general project/persistence traversal errors, failed content reads, the first read/inspection timeout in each subtree, and files rejected by the 100 MB content limit. Missing explicit persistence roots also warn; absent optional default installation paths do not.

**How it works:** Reading and inspecting a selected file together are bounded at 5 seconds. Recognized font and supported asset containers are checked from their first 32 bytes; their bodies are not searched for embedded scripts and their size does not produce a coverage warning. Text disguised as a font still receives content checks. General-source candidates with binary prefixes stop after at most 8 KiB, before full-file allocation or reading. Other selected files, including text candidates and targeted application entrypoints, are read in full below 100 MB (100,000,000 bytes); files at or above that limit are not content-checked and report `size limit exceeded`. Processing timeouts are tracked per subtree — keyed on the first three path components below the home directory, which resolves the cloud-provider layouts that matter (`Library/CloudStorage/Dropbox`, `Library/CloudStorage/OneDrive-Foo`) without lumping all of `~/Library` together. The first timeout emits a finding naming the subtree. After three timeouts in that subtree, further content reads there are abandoned for the rest of the scan.

**Why this matters:** Files under Dropbox, OneDrive, iCloud Drive, or Google Drive often exist only as placeholders whose contents live on the provider's servers. Opening one asks the provider to fetch it. Usually that works, and it *should* — cloud-synced folders hold real repositories, and skipping them outright would be a blind spot in exactly the kind of place this campaign spreads. But when the provider is offline, the account is unlinked, or the file is gone server-side, the read blocks indefinitely and then fails. The same happens on a stalled NFS or SMB mount.

A timeout alone bounds each file but not the scan: an offline Dropbox folder holding a few hundred build configs would cost 5 seconds times every one of them. Three strikes is enough to tell "one odd file" from "this whole mount is not answering," and caps the cost at 15 seconds per subtree.

Coverage limitations appear in a compact, separate summary in text output; they are not counted as attack indicators. The summary counts size-limit failures, permission denials, timeouts, Git errors, network collection errors, and other errors separately. Coverage failures list paths grouped by category and shared cause: each explanation appears once, followed by sorted affected paths. Routine scope notices are summarized by category, with exact paths retained in JSON. JSON retains each exact error or read limit. JSON retains individual `scan-incomplete` records, and incomplete coverage still produces a nonzero exit status and an explicit qualification in the final result.

### 22. `patched-application` (CRITICAL)

Checks documented VS Code, Cursor, Antigravity, GitHub Desktop, and Discord entrypoints for known payload markers or references to `.inz.cjs` / `.inz.orig`. Application presence, a generic `require()`, and arbitrary date-like comments do not trigger findings.

| Target | Files inspected | Source attack |
|--------|-----------------|---------------|
| VS Code / Cursor / Antigravity | `node_modules/@vscode/deviceid/dist/index.js`; `out/main.js` where present | PolinRider (DPRK / Contagious Interview) |
| GitHub Desktop | `resources/app/main.js` (`Contents/Resources/app/main.js` on macOS) | PolinRider (DPRK / Contagious Interview) |
| Discord | Versioned `modules/discord_desktop_core*/discord_desktop_core/index.js` | PolinRider (DPRK / Contagious Interview) |

The default scan checks these paths independently of the home walk and dependency boundaries. Conventional installation layouts include macOS `/Applications` and `~/Applications`; Windows Program Files, LocalAppData Programs and versioned GitHubDesktop directories; and Linux `/usr/share`, `/usr/lib`, `/opt`, and `~/.local/share`. Discord data directories use macOS Application Support, Windows AppData, or Linux XDG config. Exact discovery patterns are in `ApplicationEntrypointGlobs` in `ioc.go`.

Adjacent `*.inz.cjs` / `*.inz.orig` files produce `malicious-repo-artifact` findings even if the entrypoint is absent. Duplicate discovery of the same path is suppressed. Entry files below 100 MB are fully inspected, including their middle and tail. Files at or above that limit receive a `scan-incomplete` size-limit warning. Reading and inspection share one five-second deadline. Access/read failures also produce `scan-incomplete` warnings. No application or package manager is executed.

Persistence discovery shares the project walk under home and recursively searches `/usr/local/lib`, `/opt`, `/usr/lib`, and `/usr/share` on Unix, plus `/Applications` on macOS; Windows searches home and Program Files. Discovery crosses dependency directories by default and recognizes renamed app bundles and custom npm prefixes. It reads selected entrypoints, not every file's contents. The public [NullReceiver scanner](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/scan_macos.sh) supplies the recursive sidecar/entrypoint approach; [StepSecurity](https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise) documents the application targets. Search roots are coverage choices, not additional IOCs.

Use `-root /custom/path` (repeatable) to add locations to the full project and Python package scans, including existing content, artifact, and persistence checks. Home and system checks still run. On Windows, home is the user profile and the help text lists the configured Program Files paths for system persistence searches; Unix help uses `~` and its platform-specific system roots. Dependency content selection and targeted persistence checks apply in all roots. Explicit roots expand discovery locations, not permission to read every source/text file. Recognized browser caches still require `-browser-cache` and raw npm stores require `-npm-cache`; this is not an every-file content scan. `.git` directories are excluded from ordinary content traversal; Git history receives the separately documented exact-hash checks by default. Root symlinks are resolved; directory symlinks encountered within a tree are not traversed. Supply their destination as another root when needed. Overlapping recursive roots are deduplicated. ASAR archives are not unpacked. Signature matching normalizes fixed-width ASCII escapes but does not unpack or execute obfuscated code, and absence of a marker does not establish that the host was never compromised.

### 23. `font-execution-task` (CRITICAL)

Checks `.vscode/tasks.json` for a `folderOpen` task that executes a font-extension file with Node.js. This catches the published fake-font task even if the font has been removed and the task contains no payload signature.

JSON comments and trailing commas are accepted. The check supports command strings, quoted command objects, separate string or quoted-object arguments, and Windows/Linux/macOS command overrides. It recognizes direct Node commands and shell command boundaries, including the POSIX/Windows fallback form. It does not emulate a shell or resolve variables and task dependencies. Legitimate automatic watchers, an echoed command, or a font passed to a normal JavaScript conversion script are not findings. `task.allowAutomaticTasks` alone is not an IOC.

Source attack: PolinRider (DPRK / Contagious Interview), from OpenSourceMalware's fake-font/automatic-task reporting and ByteGuard's public task detection.

### 24. `runtime-staging-artifact` (WARN)

Checks `~/.node_modules/node_modules/` and `get-pip.py`, `.pip`, and `.npm` in the OS temporary directory (also `/tmp` and `/var/tmp` on Unix). These paths are documented by the NullReceiver IR kit. Their presence has legitimate explanations, so they are warnings to correlate with payload/persistence findings, never standalone proof of compromise. The user's ordinary `~/.npm` cache is not flagged by this check.

Source attack: PolinRider (DPRK / Contagious Interview).

### 25. `git-payload-hash` (CRITICAL)

Matches raw blob SHA-256 against the two entries in the [active hash list](#active-payload-hashes), independent of names and the checked-out branch. Source attacks: keyv npm compromise and PolinRider (DUNE incident-specific IOC). A hit can be confined to historical commits; inspect the reported object before drawing conclusions about current files or execution. Git collection failures are `scan-incomplete` warnings, not malware findings.

### 26. `scan-limited` (INFO)

Reports expected scope limits, currently shallow Git repositories whose older history is not available locally. These notices are grouped by shared explanation in human output and retained individually in JSON. They are not attack indicators or scan failures and do not change the exit status. Actual inspection failures remain `scan-incomplete` warnings.

## Acknowledgments

Checks draw on public incident analyses, community scanner implementations, and the explicitly authorized local DUNE hash. Broader heuristics are review warnings, with their provenance and limits documented separately. Their researchers did the actual reverse engineering, payload extraction, and infrastructure attribution — surplies is just a thin Go wrapper that mechanizes their IOCs for local inspection of a developer machine.

Sources, in rough order of how much of the IOC set they contribute:

- **[StepSecurity](https://www.stepsecurity.io/)** ([blog](https://www.stepsecurity.io/blog)) — the bulk of the IOC set, including the full axios, litellm, and Mini Shai-Hulud writeups, plus Joyfill application-persistence markers and targets.
- **[Socket](https://socket.dev/)** — Joyfill RAT persistence markers, targets, stage paths and boot key; the PolinRider campaign framing, DPRK / Contagious Interview attribution, and the cross-ecosystem affected-package list with versions (npm, Packagist, PyPI) that the version checks are built from, plus the Packagist-wave payload hashes and C2 IPs; broader package coverage for the Mini Shai-Hulud campaign across npm, PyPI, and Composer ecosystems, the campaign-level attribution to TeamPCP, the Mini Shai-Hulud attribution and payload hashes for the June 1, 2026 Red Hat Cloud Services wave (plus the `tmp.0987654321.lock` / `/tmp/b-*/b.zip` Bun-loader artifacts), and the full IOC set for the TrapDoor crypto-stealer campaign (npm, PyPI, and Crates.io phantoms; `ddjidd564` actor attribution; `trap-core.js` payload; `.cursorrules` / `CLAUDE.md` AI-persistence vector).
- **[OpenSourceMalware](https://opensourcemalware.com/)** ([blog](https://opensourcemalware.com/blog), [PolinRider dossier](https://github.com/OpenSourceMalware/PolinRider)) — the original PolinRider filesystem IOC set: both generations of loader signature constants (`("rmcej%otb%",2857687)` / `_$_1e42`, rotated to `Cot%3t=shtP` / `MDy`) and the `global['!']` / `global['_V']` injection markers, the infected-file-type list and the ~280-space padding pattern, the `temp_auto_push.bat` and `config.bat` propagation artifacts plus the `config.bat` line injected into `.gitignore`, the `fa-solid-400.woff2` and `spellright.dict` loader hiding places, the `npm/lib/cli.js` overwrite, the attacker-published Tailwind typosquat list, the interim C2 IP block list, and the `fetch-page-assets` case study (five versions live and unflagged on npm, plus the `global.i="A8-3292-*"` campaign-tag markers and the NullReceiver wallet linking PolinRider to the Ethereum dead-drop C2).
- **[TanStack](https://tanstack.com/)** — postmortem and IOCs for the Mini Shai-Hulud sub-incident that hit 42 `@tanstack/*` packages on May 11, 2026 (`@tanstack/setup` phantom, `router_init.js` payload filename, `seed{2,3}.getsession.org` / `litter.catbox.moe`, the pwn-request → Actions cache poisoning → OIDC token vector).
- **[Endor Labs](https://www.endorlabs.com/)** — GlassWorm variation-selector ranges and invisible-payload behavior; used for contextual Unicode warnings.
- **[Aikido](https://www.aikido.dev/)** — GlassWorm Unicode-concealment research; also `tanstack_runner.js` payload filename (with SHA-256 hash) and `execution.js` as the alternate Bun-loaded payload name across the Mini Shai-Hulud campaign, plus the `"prepare": "bun run tanstack_runner.js && exit 1"` lifecycle pattern.
- **[SafeDep](https://safedep.io/)** — the May 19, 2026 @antv-wave writeup: full 317-package compromise list, `@antv/setup` phantom + `github:antvis/G2#<imposter-commit-sha>` `optionalDependencies` vector, the `t.m-kosche.com` C2 endpoint (disguised as OpenTelemetry traces), the kitty-monitor persistence variant (`~/.local/share/kitty/cat.py`, `kitty-monitor.{service,plist}`, `/var/tmp/.gh_update_state`), and `.claude/index.js` as the payload-copy committed into repos.
- **[OSV](https://osv.dev/)** / the [GitHub Advisory Database](https://github.com/advisories) — the NullReceiver loader's own constants (the C2-resolver wallet `0xa322e5f3…`, the `/0x/cls` and `/0x/ls` fetch paths, `plugin.js` as a carrier name, exact cls/ls XOR keys, and the payload response-header name), and the authoritative affected-version *ranges* behind several package pins, which incident writeups routinely under-state because they name only the version the analysis ran against. `fluid-type-ui` is the case in point: OSM documents `2.0.8`, while [MAL-2026-11136](https://osv.dev/vulnerability/MAL-2026-11136) / [GHSA-4w4v-pw3v-q85q](https://github.com/advisories/GHSA-4w4v-pw3v-q85q) mark `2.0.9` affected too — the version a victim would plausibly have upgraded into. Machine-readable and versioned, so unlike a blog post it cannot be edited out from under a citation.
- **[NullReceiver IR kit](https://github.com/OsamaCodes62/nullreceiver-ir-kit)** (Osama Ehsaan) — `*.inz.cjs` sidecars, macOS application roots, patched deviceid/GitHub Desktop entrypoints, additional stage paths, recipient marker, and runtime/staging paths. This community source is corroborated by matching campaign constants and registry advisories; the application targets are also documented by Socket and StepSecurity.
- **[ByteGuard](https://github.com/n0m4dz/ByteGuard)** — community corroboration of `__inzCR`, `/*M260630A*/`, `.inz.orig`, VS Code `out/main.js`, and Node-to-font task detection. Also informs contextual loader, task/settings, toolchain-discovery, asset-header and source heuristics; upstream severities are not inherited.

- **[Snyk](https://snyk.io/)** — the August 4, 2026 keyv npm compromise writeup: full 11-package malicious release list under maintainer `jaredwray`, `setup.mjs` / `Math_Symbol.js` payload hashes, the `"preinstall": "node setup.mjs"` lifecycle pattern, `.claude/math_init.js` and IDE-hook (SessionStart / folderOpen) persistence path, and trusted-provenance attestation of the malicious build.

- **Local DUNE incident investigation** — the exact fake-font dropper SHA-256, Git blob identity and size in the [active hash list](#active-payload-hashes). Independently verified locally and explicitly requested by the developer; not an independent public campaign source.

The public writeups below support the public indicators; the incident-specific DUNE exception is documented separately above:

- [axios Compromised on npm: Malicious Versions Drop Remote Access Trojan](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) (StepSecurity)
- [LiteLLM Credential Stealer Hidden in PyPI Wheel](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel) (StepSecurity)
- [Mini Shai-Hulud Is Back: A Self-Spreading Supply Chain Attack Hits the npm Ecosystem](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) (StepSecurity)
- [Mini Shai-Hulud supply chain attack tracker](https://socket.dev/supply-chain-attacks/mini-shai-hulud) (Socket)
- [Postmortem: TanStack npm supply-chain compromise](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem) (TanStack — Mini Shai-Hulud TanStack sub-incident)
- [Mini Shai-Hulud Is Back: npm Worm Hits over 160 Packages, including Mistral and Tanstack](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) (Aikido — Mini Shai-Hulud TanStack sub-incident)
- [Mini Shai-Hulud Strikes Again: 314 npm Packages Compromised](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/) (SafeDep — Mini Shai-Hulud @antv wave)
- [Multiple redhat-cloud-services npm Packages Compromised](https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised) (StepSecurity — Mini Shai-Hulud Red Hat Cloud Services wave; full 31-package version list)
- [Mini Shai-Hulud Campaign Hits Red Hat Cloud Services npm Packages](https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages) (Socket — Mini Shai-Hulud Red Hat Cloud Services wave; attribution + payload hashes + temp artifacts)
- [TrapDoor Crypto Stealer Supply Chain Attack Hits 34 Packages and Hundreds of Versions Across npm, PyPI, and Crates.io](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates) (Socket — TrapDoor campaign)
- [Inside the keyv npm Supply Chain Compromise](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/) (Snyk — keyv npm compromise; 11 malicious releases, payload hashes, IDE hooks)
- [PolinRider: North Korea-Linked Supply Chain Campaign Expands Across Open Source Ecosystems](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) (Socket — PolinRider campaign framing and attribution)
- [PolinRider supply chain attack tracker](https://socket.dev/supply-chain-attacks/polinrider) (Socket — full affected-package list with versions across npm, Packagist, and PyPI)
- [PolinRider Expands to GitHub and Packagist](https://socket.dev/blog/polinrider-github-packagist) (Socket — Packagist wave; payload hashes, C2 IPs, NullReceiver wallet)
- [PolinRider: DPRK Threat Actor Implants Malware in Hundreds of GitHub Repos](https://github.com/OpenSourceMalware/PolinRider) (OpenSourceMalware — campaign dossier; signature constants for both variants, YARA rules, infected-file-type table, typosquat list)
- [A Developer's Guide to Getting Rid of PolinRider](https://opensourcemalware.com/blog/developer-guide-getting-over-polinrider) (OpenSourceMalware — host artifacts, padding pattern, `npm/lib/cli.js` overwrite, `.gitignore` injection, interim C2 IP list)
- [NPM Isn't Prepared For North Korean PolinRider Attack](https://opensourcemalware.com/blog/polinrider-npm-case-study-dprk-attack) (OpenSourceMalware — `fetch-page-assets` case study; live unflagged versions, payload hashes, `global.i="A8-…"` markers)
- [NullReceiver's Blank Crypto Transfers Solves the Challenges of EtherHiding](https://opensourcemalware.com/blog/nullreceiver-dprk-c2-technique) (OpenSourceMalware — blockchain dead-drop C2 technique; `bianira-ui` / `fluid-type-ui` npm artifacts)
- [MAL-2026-11136](https://osv.dev/vulnerability/MAL-2026-11136) / [MAL-2026-11132](https://osv.dev/vulnerability/MAL-2026-11132) (OSV / GitHub Advisory Database, findings credited to Amazon Inspector — the C2-resolver wallet, the Ethereum JSON-RPC endpoint set, the `/0x/cls` and `/0x/ls` fetch paths, the XOR-then-`eval` and `node -e` execution, `src/index.js` and `plugin.js` as carriers, and the affected-version ranges for `fluid-type-ui` and `bianira-ui`)
- [nullreceiver-ir-kit](https://github.com/OsamaCodes62/nullreceiver-ir-kit) (Osama Ehsaan — `iocs/iocs.csv` and `scan_macos.sh`: the `*.inz.cjs` IDE-injection sidecars and the patched `@vscode/deviceid` / GitHub Desktop entrypoints)

- [Joyfill npm supply-chain compromise](https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise) (StepSecurity — exact persistence sentinels, Discord and other application targets)
- [Joyfill beta releases and DEV#POPPER](https://socket.dev/blog/joyfill-npm-beta-releases-compromised) (Socket — persistence sentinels, target files, `/0x/js`, and `ThZG+0jfXE6VAGOJ`)
- [MAL-2026-15636](https://osv.dev/vulnerability/MAL-2026-15636) (Amazon Inspector via OSV — exact cls/ls XOR keys)
- [MAL-2026-12324](https://osv.dev/vulnerability/MAL-2026-12324) (Amazon Inspector via OSV — `X-Payload-B64` response header)
- [ByteGuard detection rules](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json) and [scanner implementation](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts) (community — exact loader markers, backup suffix, VS Code entrypoint, and fake-font task detection)

If surplies is useful to you, the credit belongs to them. Go read their writeups.

## License

MIT


- [Endor Labs GlassWorm report](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode) — Unicode technique and both variation-selector ranges.
- [Aikido GlassWorm research](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode) — additional public research on invisible source payloads.

## Expanded checks and scope decisions

| Check / coverage | Behavior | Evidence |
|---|---|---|
| Network collection | Five-second collector/resolver deadline; errors and timeouts are `scan-incomplete`. NXDOMAIN and successful but filtered/empty DNS answers have distinct `scan-limited` notices. Only established TCP **remote** endpoints match; listeners, local addresses, other connection states and UDP are outside this snapshot check. IPv4-mapped IPv6 normalizes to IPv4. | Local correctness fixes; existing C2 indicators unchanged. |
| Package metadata and lifecycle targets | Project and installed manifests are parsed with bounded reads. Invalid/unreadable manifests and selected missing scripts report incomplete coverage. Hooks: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepack`, `postpack`. Quoted JS/CJS/MJS targets are supported; arbitrary shell syntax and options are not interpreted. Generic obfuscation is WARN, not proof of infection. | [npm lifecycle semantics](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [OSM task/lifecycle analysis](https://opensourcemalware.com/blog/how-malware-abuses-npm-lifecycle-scripts-and-vs-code-tasks), [NIK CI source](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/ci/scan_repo.sh). |
| `loader-variant`, `loader-structure`, `correlated-loader-markers` | Quote/spacing variants, immediate local-CJS loader calls, and markers correlated with loader/decode structure produce WARN. Generic `createRequire`, dates, and extra marker names alone do not. | [ByteGuard rules](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json); community-pattern evidence. |
| Additional toolchains | Targeted npm `bin/npm-cli.js`, Yarn `lib/cli.js`, Corepack `dist/pnpm.js`, pnpm `bin/pnpm.cjs`, npx-cached `pnpm.cjs`, and Claude version files are inspected by default, within home, added roots, and existing system persistence roots. Presence/size alone is not a finding for these added targets. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts); defensive discovery, not independent infection confirmation for every product. |
| `disguised-file-execution-task`, `workspace-setting-context` | Broader interpreters and binary-named targets warn, including manual tasks and platform overrides. Automatic Node-to-font remains CRITICAL. Ordinary automatic builds and hidden output alone are not flagged. Settings are context; invalid values are INFO. Multiple risky/contextual preferences warn without claiming a trust bypass. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts), [Microsoft task semantics](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior). |
| `startup-content`, `hosts-c2-entry` | Inspect shell startup files, macOS launch directories, Linux systemd/cron locations, and the system hosts file for contextual known indicators. Comments are ignored. Binary plists produce an explicit scope notice; no plist decoder or external command is invoked. Windows startup APIs/registry enumeration remain outside scope. | [NIK macOS](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_macos.sh), [NIK Linux](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/7bd74b580639c7eae5ccc0930521c6e7d6da8d6d/scan_linux.sh); community hunts, not DUNE attribution. |
| `asset-format-mismatch` | WARN for unsupported/truncated headers or text in PNG/JPEG/GIF/WebP/ICO/WASM/PDF/ZIP/MP3/MP4. Headers are format hints, not full validators. Bounded whitespace/NUL padding is removed for script inspection. Existing font magics and HTML/XML download-error exclusions remain. | [ByteGuard scanner](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/src/scanner.ts). |
| `unicode-concealment`, `escaped-execution`, `suspicious-source-execution` | WARN for unbalanced bidi controls, ASCII-identifier joiners, runs of at least eight variation selectors in either Unicode range, correlated escaped execution, decode/execute, download-to-shell, or hidden detached spawn structure. No long-line cutoff. Ordinary emoji, balanced RTL, international joiners, private-use glyphs, `eval` alone and public RPC URLs alone do not trigger these general-source checks. | [Endor Labs](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode), [Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode), [ByteGuard rules](https://github.com/n0m4dz/ByteGuard/blob/ac0f609ecdfeab88d731ed7b47ffdf38deb8256d/rules/default.rules.json). |

Live telemetry decision (G15): retain the bounded network snapshot. Process command lines/ancestry, registry and scheduled-task APIs, memory, protocol capture, and dynamic blockchain queries are deferred to complementary endpoint/network investigation. No additional runtime collectors, C2 connections, remediation, or account actions are added. Static findings do not establish execution; a clean scan cannot rule out a running or historical implant.

Explicit package checks follow package-directory symlinks (including pnpm layouts). The scanner resolves requested root symlinks and follows selected file symlinks, but does not recursively follow internal directory symlinks. Supply their destinations with `-root`. Directory traversal itself is not subject to the per-file processing deadline. Package-target checks can inspect a lifecycle target separately from an earlier ordinary source read; repeated identical findings are deduplicated.


### Content I/O reporting

Default scans include dependency inspection, Git history checks, and coverage details, with dependency reads selected by manifests and known candidates rather than every eligible dependency file. Selected general source checks exclude binary bodies after an 8 KiB prefix rather than reading an entire extensionless cache object before discovering that it is binary. Text candidates retain whole-file checks within the existing size/time limits. Known exact-hash filenames, lifecycle targets, selected package metadata and targeted persistence entrypoints keep their existing inspection policy. Recognized assets still need only their headers; leading NUL/whitespace padding does not prevent inspection of disguised script assets.

The summary reports bytes returned by content-file reads and the number of binary-prefix exclusions. The count includes prefix and failed reads, but excludes filesystem metadata, OS read-ahead and Git subprocess I/O; it is not a replacement for Activity Monitor's process I/O counter. Verbose output also reports cumulative content reads and the current path approximately every GiB. Binary exclusions appear as one aggregate scope notice rather than one finding per cache object.


### Raw npm cache policy

Full scans skip directories named `_cacache` **before enumerating their contents**, across project, Python, persistence and Git discovery. This avoids reading npm's opaque content-addressed HTTP/package storage as though every object were installed source. The distinction from npx's executable installation cache follows [npm's cache documentation](https://docs.npmjs.com/cli/v11/commands/npm-cache/).

Each excluded store is logged immediately and appears once as an informational `scan-limited` record in text/JSON output. This is an explicit coverage exclusion, not a claim that cached data is safe. An explicitly added `-root` does not override it. Use `-npm-cache` to opt into raw cache inspection; full scans do not enable this expensive option. Archives still are not unpacked.

Installed `node_modules` and `.npm/_npx` installations retain metadata/lifecycle checks and deep declared-entrypoint inspection. Executable plugin caches retain source checks outside dependency boundaries. Extracted uv package bodies are not broadly read; known candidate names and nested installed-package metadata remain discoverable.

### Performance diagnostics

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

### Routine content scope

Routine scans select files for specific checks:

- package manifests, lifecycle targets and declared deep entrypoints;
- startup/toolchain/application persistence targets and known artifact/hash candidates;
- documented injection filenames (`App.js`, `index.js`, `truffle.js`, `tasks.json`, `cli.js`, `plugin.js`), JavaScript/TypeScript `*.config.*`, and direct `.claude`/`.vscode` settings;
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
Absent build/pack hook targets in installed npm packages are scope notices;
missing install/postinstall targets and other actual read failures remain coverage
errors. Non-npm update manifests are not parsed as npm versions merely because
they are named `package.json`.
