# surplies

[![Go Report Card](https://goreportcard.com/badge/github.com/astrostl/surplies)](https://goreportcard.com/report/github.com/astrostl/surplies)

> **Disclaimer:** This tool is vibe coded and provided as-is, without warranty or guarantee of any kind. It may produce false positives, miss indicators, or behave unexpectedly. Use it as one signal among many, not as a definitive security verdict. Testing has only been performed on macOS — Linux and Windows behavior is untested.

A cross-platform CLI tool that scans your home directory (and well-known system Python paths) for evidence of supply chain attacks via compromised dependencies. Pure Go, zero dependencies.

**Currently detects indicators from five documented major supply chain attacks**, sourced from incident writeups by [StepSecurity](https://www.stepsecurity.io/), [Socket](https://socket.dev/), [Aikido](https://www.aikido.dev/), [SafeDep](https://safedep.io/), [Snyk](https://snyk.io/), and the [TanStack](https://tanstack.com/) team (see [Acknowledgments](#acknowledgments)):

- **[axios npm compromise](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)** — compromised maintainer account published `axios@1.14.1` and `axios@0.30.4` with a phantom dependency (`plain-crypto-js`) that deployed a cross-platform RAT
- **[litellm PyPI compromise](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel)** — malicious `litellm@1.82.7` and `1.82.8` harvested credentials (SSH, AWS, GCP, Azure, env files) and installed a persistent C2 backdoor via systemd
- **[TrapDoor crypto-stealer campaign](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)** (attributed to GitHub actor `ddjidd564`, campaign marker `P-2024-001`, May 2026) — 34 purpose-built phantom packages across npm (21), PyPI (7), and Crates.io (6) impersonating crypto / DeFi / AI developer tooling. npm packages drop `trap-core.js` (48 KB, XOR-encrypted with key `cargo-build-helper-2026`) via `postinstall`, which writes `.cursorrules` and `CLAUDE.md` into the project directory for AI-assistant-driven persistence and pulls runtime config from `ddjidd564.github.io/defi-security-best-practices/`. surplies covers the npm and PyPI phantoms; Crates.io is out of scope (no Cargo scanner today).
- **[Mini Shai-Hulud campaign](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)** (attributed to TeamPCP, April–May 2026) — an ongoing self-spreading credential-theft worm across npm, PyPI, and Composer. The bulk of the campaign uses compromised maintainer accounts with "double-tap" publishing across `@uipath/*`, `@squawk/*`, `@tallyui/*`, `@mistralai/*`, `safe-action`, `@cap-js/*`, `intercom-client`, PyPI `lightning`/`guardrails-ai`/`mistralai`, Composer `intercom/intercom-php`, and many more. On May 11 a distinct sub-incident hit 42 `@tanstack/*` packages (84 versions) via a different initial-access vector: a fork PR poisoned a GitHub Actions cache, then an attacker-controlled binary extracted an OIDC token from runner memory and published directly to npm — same campaign payload family (`router_init.js`, Session-network exfil via `filev2.getsession.org` / `seed{1,2,3}.getsession.org`, self-propagation), different door in. On May 19 the campaign struck again with the AntV maintainer compromise: 317 packages across `@antv/*`, `@lint-md/*`, and AntV-adjacent unscoped (`echarts-for-react`, `timeago.js`, `size-sensor`, and the rest of the visualization-ecosystem surface) published with the same "double-tap" pattern, a new `@antv/setup` phantom pulled from `github:antvis/G2#<imposter-commit-sha>`, a new C2 endpoint (`t.m-kosche.com`, disguised as OpenTelemetry traces), and a new kitty-monitor persistence variant (`~/.local/share/kitty/cat.py` + `kitty-monitor.{service,plist}`) — same Mini Shai-Hulud toolkit (Bun runtime, hex obfuscation, `firedalazer` GitHub dead-drop trigger, Dune-themed exfil repo naming) per SafeDep's writeup. On June 1 the campaign hit 31 `@redhat-cloud-services/*` packages, published after an attacker minted an npm token from a GitHub Actions OIDC credential stolen from the `RedHatInsights/javascript-clients` repo — same payload family (`preinstall` → `node index.js` → encrypted Bun loader harvesting GitHub Actions secrets, npm tokens, cloud/Kubernetes/Vault material, and SSH/Git credentials). Notably, this wave exfiltrates over a legitimate, non-actor-owned endpoint rather than dedicated C2 infrastructure, so no new network IOC is added; per Socket's writeup.
- **[keyv npm compromise](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)** (August 4, 2026) — compromised release path for maintainer `jaredwray` published 11 malicious releases across `keyv@6.0.0`, `@cacheable/*`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, and `ecto@5.0.1`. Each tarball adds `"preinstall": "node setup.mjs"` plus two payload files (`setup.mjs` 29,918 bytes; `Math_Symbol.js` 727,680 bytes, byte-identical across all affected releases). A second execution path injected Claude Code `SessionStart` and VS Code `folderOpen` hooks (`.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/setup.mjs`) into the keyv repository. The malicious `keyv@6.0.0` release carried valid npm trusted provenance signed by GitHub Actions.

## Design principles

- **Filesystem-first detection.** Never shells out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any package manager/runtime tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scans files on disk instead. The sole exception is `netstat`, used only for live network connection IOC matching where no filesystem equivalent exists.
- **Report only, never remediate.** Read-only scanner. Never deletes files, uninstalls packages, modifies configs, or takes any corrective action. Findings are reported; the user decides what to do.
- **No container/orchestrator checks.** Does not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem.
- **Cross-platform.** All checks work on macOS, Linux, and Windows (amd64 and arm64).
- **Zero dependencies.** stdlib only. No third-party Go modules.

## Install

**Homebrew (macOS):**

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
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
surplies -q           # quiet mode (suppress scan details)
surplies -json        # JSON output (findings array to stdout)
surplies -version     # print version
```

Progress and stats go to stderr. Findings go to stdout. This means `-json` output is clean for piping:

```sh
surplies -json | jq '.[] | select(.severity == "CRITICAL")'
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan, no indicators found |
| 1 | Warning-level findings only |
| 2 | At least one critical finding |

## Scan phases

The scanner runs five phases sequentially:

1. **Known malicious artifacts** — check fixed filesystem paths for dropped payloads
2. **Project directory scanning** — walk home directory once, inspecting every `node_modules` for compromised packages, every Composer `vendor/` for compromised packages, and every `.claude/` / `.vscode/` for project-local payload files
3. **Python site-packages scanning** — walk home directory + system Python paths, inspect every `site-packages`
4. **Network IOCs** — check active connections from `netstat -n` against known C2 IPs (and IPs resolved on-the-fly from known C2 domains)
5. **Temp directory artifacts** — check temp dirs for payload remnants

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

**How it works:** For each `node_modules` directory, reads `package.json` for every package in the known-bad list and compares the installed version string.

**Why this matters:** These versions were published to npm by either compromised maintainer accounts or maintainers acting maliciously. Lock files and caches can pin you to a bad version long after it's been unpublished from the registry.

---

### 4. `suspicious-install-script` (WARN)

Scans every npm package's `package.json` for `preinstall`, `install`, `postinstall`, and `prepare` lifecycle scripts that contain patterns commonly used by malware. (`prepare` is included because the Mini Shai-Hulud TanStack sub-incident used `"prepare": "bun run tanstack_runner.js && exit 1"`; npm runs `prepare` on local installs and on `npm pack`, so it's a viable malware vehicle.)

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

**How it works:** Reads every `package.json` in every `node_modules` directory (including scoped packages under `@org/`). Checks each lifecycle script against the pattern list. Reports the script content (truncated to 80 chars) and all matched flags.

**Why this matters:** The axios attack used a `postinstall` hook in `plain-crypto-js` to run `node setup.js`, which then used `curl`/`powershell`/`osascript` to download and execute RAT payloads. Legitimate packages rarely need to download executables or run shell commands during install.

---

### 5. `obfuscated-install-script` (CRITICAL)

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

**How it works:** Only inspects JS files that are directly referenced by lifecycle scripts (not every JS file in the package). Reads the file content and counts occurrences of each pattern.

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

**How it works:** During the home-directory walk, any `vendor/` directory that contains a `composer/installed.json` is identified as a Composer install. The scanner parses both Composer 1.x (flat array) and 2.x (`{packages: [...]}`) envelope formats, then compares each installed package against the known-bad list. A leading `v` on either the installed or known-bad version string is stripped so `v5.0.2` and `5.0.2` both match.

**Why this matters:** The Mini Shai-Hulud worm's reach extended beyond npm into PyPI and Composer/Packagist. Detection here mirrors the npm and Python version checks for cross-ecosystem coverage of the same campaign.

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

**How it works:** Runs `netstat -n` (numeric output, no reverse DNS) in parallel with forward DNS lookups (5s timeout) for each known C2 domain. Each known C2 IP — both the hardcoded entries and the IPs resolved from C2 domains — is then substring-matched against the netstat output. Forward DNS on the small known-bad list takes well under a second, whereas reverse DNS on every active connection (the prior approach) can take minutes on a busy machine. Attackers control forward DNS for their domains but not reverse DNS for the IPs they're hosted on, so forward resolution is also more reliable. Unspecified addresses (`0.0.0.0`, `::`) and loopback addresses are dropped from the resolved-IP set before matching, so DNS-sinkholed domains can't false-positive against every listener line in netstat output.

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

**How it works:** The home-directory walk (the same one used for `node_modules`) returns `SkipDir` when it encounters a `.claude/` or `.vscode/` directory after running `os.Stat()` on each known malicious filename inside. No content inspection is performed — the filenames themselves are not used by legitimate Claude Code or VS Code configurations, so presence alone is the signal.

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

## Acknowledgments

Every IOC, malicious filename, C2 domain, persistence path, and obfuscation pattern checked by this tool was lifted directly from incident analyses published by others. Their researchers did the actual reverse engineering, payload extraction, and infrastructure attribution — surplies is just a thin Go wrapper that mechanizes their IOCs so you can sweep a developer machine for them in a few seconds.

Sources, in rough order of how much of the IOC set they contribute:

- **[StepSecurity](https://www.stepsecurity.io/)** ([blog](https://www.stepsecurity.io/blog)) — the bulk of the IOC set, including the full axios, litellm, and Mini Shai-Hulud writeups.
- **[Socket](https://socket.dev/)** — broader package coverage for the Mini Shai-Hulud campaign across npm, PyPI, and Composer ecosystems, the campaign-level attribution to TeamPCP, the Mini Shai-Hulud attribution and payload hashes for the June 1, 2026 Red Hat Cloud Services wave (plus the `tmp.0987654321.lock` / `/tmp/b-*/b.zip` Bun-loader artifacts), and the full IOC set for the TrapDoor crypto-stealer campaign (npm, PyPI, and Crates.io phantoms; `ddjidd564` actor attribution; `trap-core.js` payload; `.cursorrules` / `CLAUDE.md` AI-persistence vector).
- **[TanStack](https://tanstack.com/)** — postmortem and IOCs for the Mini Shai-Hulud sub-incident that hit 42 `@tanstack/*` packages on May 11, 2026 (`@tanstack/setup` phantom, `router_init.js` payload filename, `seed{2,3}.getsession.org` / `litter.catbox.moe`, the pwn-request → Actions cache poisoning → OIDC token vector).
- **[Aikido](https://www.aikido.dev/)** — `tanstack_runner.js` payload filename (with SHA-256 hash) and `execution.js` as the alternate Bun-loaded payload name across the Mini Shai-Hulud campaign, plus the `"prepare": "bun run tanstack_runner.js && exit 1"` lifecycle pattern.
- **[SafeDep](https://safedep.io/)** — the May 19, 2026 @antv-wave writeup: full 317-package compromise list, `@antv/setup` phantom + `github:antvis/G2#<imposter-commit-sha>` `optionalDependencies` vector, the `t.m-kosche.com` C2 endpoint (disguised as OpenTelemetry traces), the kitty-monitor persistence variant (`~/.local/share/kitty/cat.py`, `kitty-monitor.{service,plist}`, `/var/tmp/.gh_update_state`), and `.claude/index.js` as the payload-copy committed into repos.
- **[Snyk](https://snyk.io/)** — the August 4, 2026 keyv npm compromise writeup: full 11-package malicious release list under maintainer `jaredwray`, `setup.mjs` / `Math_Symbol.js` payload hashes, the `"preinstall": "node setup.mjs"` lifecycle pattern, `.claude/math_init.js` and IDE-hook (SessionStart / folderOpen) persistence path, and trusted-provenance attestation of the malicious build.

Specifically, the following writeups are the basis for every check in this scanner:

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

If surplies is useful to you, the credit belongs to them. Go read their writeups.

## License

MIT
