# Checks

Every check surplies runs, what it matches on, and why it exists. The severity in
each heading is the severity of the finding it produces; see
[exit codes](../README.md#exit-codes). Selection and scope rules that apply across
checks are in [Scanning behavior](SCANNING.md).

## 1. `known-artifact` (CRITICAL)

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

## 2. `phantom-dependency` (CRITICAL)

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

## 3. `compromised-version` (CRITICAL)

Checks installed npm packages against a database of known-compromised versions.

**Known compromised versions:**

| Package | Compromised versions | Attack type |
|---------|---------------------|-------------|
| `axios` | 1.14.1, 0.30.4 | RAT via phantom dependency (March 2026) |
| 100+ packages across `@uipath/*`, `@squawk/*`, `@tallyui/*`, `@beproduct/*`, `@supersurkhet/*`, `@draftauth/*`, `@draftlab/*`, `@taskflow-corp/*`, `@ml-toolkit-ts/*`, `@mesadev/*`, `@mistralai/*`, `@dirigible-ai/*`, `@opensearch-project/opensearch`, `@cap-js/*`, `@tolka/*`, and unscoped (`safe-action`, `cross-stitch`, `git-git-git`, `ts-dna`, `wot-api`, `cmux-agent-mcp`, `git-branch-selector`, `nextmove-mcp`, `agentwork-cli`, `ml-toolkit-ts`, `intercom-client`, `mbt`) | 200+ versions — see `internal/scan/ioc.go` and source blogs | Mini Shai-Hulud — main wave (Apr–May 2026) |
| 42 `@tanstack/*` packages (`react-router`, `router-core`, `start-plugin-core`, `react-start`, `solid-router`, `vue-router`, `router-cli`, and the rest of the router/start surface) | 84 versions — two per package per the "double-tap" pattern | Mini Shai-Hulud — TanStack sub-incident, pwn-request → Actions cache poisoning → OIDC token theft (May 11, 2026) |
| 317 packages across `@antv/*` (the AntV visualization framework — 279 packages including `@antv/g2`, `@antv/g6`, `@antv/l7`, `@antv/x6`, `@antv/s2`, `@antv/f2`, `@antv/graphin`, and the rest of the visualization surface), `@lint-md/*`, and unscoped AntV-adjacent packages (`echarts-for-react`, `timeago.js`, `size-sensor`, `jest-canvas-mock`, `canvas-nest.js`, `ribbon.js`, and 30 more by the same maintainer) | 600+ versions — two-to-three per package per the "double-tap" pattern | Mini Shai-Hulud — @antv wave, AntV maintainer compromise (May 19, 2026) |
| 31 packages across `@redhat-cloud-services/*` (`chrome`, `rbac-client`, `host-inventory-client`, the `frontend-components-*` family, the various `*-client` SDKs, and the `hcc-*-mcp` servers) | 31 versions — one per package | Mini Shai-Hulud — Red Hat Cloud Services wave, GitHub Actions OIDC token theft from `RedHatInsights/javascript-clients` (June 1, 2026) |
| 11 packages: `keyv`, `@cacheable/net`, `@cacheable/node-cache`, `@cacheable/memory`, `@cacheable/utils`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, `ecto` | 11 versions — one per package (`keyv@6.0.0`, `@cacheable/net@2.1.1`, `@cacheable/node-cache@3.1.2`, `@cacheable/memory@2.2.1`, `@cacheable/utils@2.5.1`, `cacheable@2.5.1`, `flat-cache@6.1.24`, `cacheable-request@13.0.20`, `file-entry-cache@11.1.6`, `cache-manager@7.2.10`, `ecto@5.0.1`) | keyv npm compromise — compromised release path for maintainer `jaredwray` (August 4, 2026) |
| 38 compromised legitimate packages whose maintainers were infected, including `fetch-page-assets`, `html-to-gutenberg`, `itsa-react-docviewer`, `@joyfill/*`, `@testrelic/*`, `@common-stack/generate-plugin`, `@vite-*/*`, `@im_ahsan/chatbot-widget`, `bianira-ui`, `fluid-type-ui`, and the `tailwind-*` / `tailwindcss-*` plugin family | 100+ versions. `fetch-page-assets` is the notable one: only `1.2.9` was ever pulled (GHSA-vxq2-vhm7-7mhq), while `1.2.10`–`1.2.14` remained live and unflagged as `latest`. Pin to `<= 1.2.8`. npm's `0.0.1-security` takedown placeholders are deliberately excluded | PolinRider (DPRK / Contagious Interview) |

**How it works:** For each installed package, reads its manifest once for both known-version matching and lifecycle analysis. Selected read/parse failures report incomplete coverage.

**Why this matters:** These versions were published to npm by either compromised maintainer accounts or maintainers acting maliciously. Lock files and caches can pin you to a bad version long after it's been unpublished from the registry.

---

## 4. `suspicious-install-script` (WARN)

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

## 5. `obfuscated-install-script` (WARN)

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

## 6. `npm-payload-file` (CRITICAL)

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

## 7. `compromised-python-version` (CRITICAL)

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

## 8. `malicious-pth-file` (CRITICAL)

Checks for known malicious `.pth` files in Python `site-packages` directories.

**Known malicious .pth files:**

| Filename | Source attack |
|----------|---------------|
| `litellm_init.pth` | litellm 1.82.8 |

**How it works:** Scans every `site-packages` directory for `.pth` files matching known malicious filenames.

**Why this matters:** Python's site module automatically executes code in `.pth` files on every interpreter startup. The litellm 1.82.8 attack placed `litellm_init.pth` (34,628 bytes) in `site-packages`, which meant the credential-stealing payload ran not just on `pip install`, but on **every subsequent Python invocation** — including unrelated scripts, Jupyter notebooks, and CI/CD jobs. This is a particularly dangerous persistence mechanism because it doesn't require importing the compromised package.

---

## 9. `suspicious-pth-file` (WARN)

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

## 10. `compromised-composer-version` (CRITICAL)

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

## 11. `network-ioc-active-connection` (CRITICAL)

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

**How it works:** Runs `netstat -n` (plus `-l` on macOS, whose default display truncates the address column mid-address on link-local IPv6 peers) under a five-second deadline, and matches against the known C2 addresses. The known C2 domains are resolved only under `-resolve`: the lookup queries nameservers the campaign may still control, and a dead domain reparked on shared hosting would resolve to an address the machine legitimately talks to, which would report as a critical. A default run states that its snapshot was compared against the addresses alone. Parses established TCP remote endpoints in macOS, Linux and Windows formats; IP matching is exact, including IPv4-mapped IPv6 normalization. Collection failures, timeouts and malformed TCP rows report incomplete coverage. DNS NXDOMAIN and successful-but-filtered/empty answers produce distinct scope notices. No C2 service is contacted.

**Why this matters:** The axios RAT and litellm C2 backdoor both beacon out programmatically — these connections won't appear in shell history. Catching an active connection to `sfrclak.com:8000` or `checkmarx.zone` at scan time is a direct indicator of a running implant.

---

## 12. `suspicious-temp-file` (WARN)

Walks the temp directories, at every depth, for files matching patterns associated with supply chain attack payloads.

**Directories checked:**

- `os.TempDir()` — `$TMPDIR` / `%TEMP%`; on macOS `/var/folders/<xx>/<hash>/T`
- `/var/folders/<xx>/<hash>/Cleanup At Startup` (macOS; contents are deleted at boot)
- `/tmp` and `/var/tmp` (Linux/macOS)
- `/dev/shm` and `$XDG_RUNTIME_DIR` — `/run/user/<uid>` (Linux)
- `%TMP%` and `%SystemRoot%\Temp` (Windows)

Only the invoking user's temp directories are in scope. Other users'
(`/var/folders/*/*/T`, `/run/user/*`, `C:\Users\*\AppData\Local\Temp`) require
root and are not read.

**Patterns:**

| Pattern | Description | Source attack |
|---------|-------------|---------------|
| `*.vbs` | A VBScript file staged in a temp directory. Matches the file type, not a payload identity: axios dropped its loader as `%TEMP%\{campaignID}.vbs` on Windows | axios 1.14.1/0.30.4 |
| `*.ps1` | A PowerShell file staged in a temp directory. Matches the file type, not a payload identity: axios dropped its payload as `%TEMP%\{campaignID}.ps1` on Windows | axios 1.14.1/0.30.4 |
| `.pg_state` | C2 state tracking file (last-downloaded URL) | litellm 1.82.7/1.82.8 |
| `pglog` | Downloaded payload staging directory | litellm 1.82.7/1.82.8 |
| `tpcp.tar.gz` | AES-256+RSA-4096 encrypted credential exfiltration archive | litellm 1.82.7/1.82.8 |
| `tmp.0987654321.lock` | Bun loader execution lock file | mini-shai-hulud (Red Hat Cloud Services wave, June 1 2026) |
| `b-*/b.zip` | Bun loader staged payload archive, extracted under `/tmp/b-*` | mini-shai-hulud (Red Hat Cloud Services wave, June 1 2026) |

**How it works:** Temp directories are walked like the home directory, on the same discovery pass, and each pattern is matched against the trailing path components of every file found. A published staging path names where one run happened to land, not the only place the name can appear: `pglog` is reported at `/tmp/pglog` and at `/tmp/npm-install-3f2a/nested/pglog` alike. Under `-skip-tmproots` the walk is skipped and each pattern is matched only at the top of each default temp directory, so the nested example is not. Roots are resolved before walking, so `/tmp` and `/private/tmp` — or `%TEMP%` and `%TMP%` — are one walk, not two.

**Why this matters:** Temp directories are common staging grounds for supply chain payloads because they're writable without elevated privileges and often excluded from security monitoring. The axios attack staged a VBScript dropper (`%TEMP%\{campaignID}.vbs`) and a PowerShell payload (`%TEMP%\{campaignID}.ps1`) on Windows; both are self-deleting. The litellm attack used `/tmp/.pg_state` to track which C2 commands had been executed, `/tmp/pglog` for downloaded binaries, and assembled stolen credentials into `/tmp/tpcp.tar.gz` before exfiltration.

---

## 13. `project-artifact` (CRITICAL)

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

**How it works:** The home-directory walk (the same one used for `node_modules`) returns `SkipDir` when it encounters a `.claude/` or `.vscode/` directory after running `os.Stat()` on each known malicious filename inside. The named artifact checks use presence alone. The same-directory content scan also reads `tasks.json` for payload signatures and automatic Node-to-font execution, and descends into nested files.

**Why this matters:** The Mini Shai-Hulud worm modifies project-local config to ensure the payload runs the next time a developer opens that project. Editing `.claude/settings.json` with a `SessionStart` hook makes the next `claude` invocation in that repo execute `.claude/router_runtime.js`; editing `.vscode/tasks.json` with a `folderOpen` task makes the next VS Code window opened in that repo execute `.vscode/setup.mjs`. The keyv npm compromise used the same IDE-hook pattern, committing `.claude/setup.mjs`, `.claude/math_init.js`, and `.vscode/setup.mjs` into the keyv repository (verified `github-actions[bot]` commit) so that opening the project in Claude Code or VS Code re-triggers the loader even without an npm install. The malicious files survive `git clean` against most ignore lists, persist across `node_modules` reinstalls, and re-trigger exfiltration on every developer session — finding the payload file is often the only reliable signal that a project was touched, since the lifecycle hook itself is short and easy to miss in a diff.

---

## 14. `phantom-python-package` (CRITICAL)

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

## 15. `fake-font-payload` (CRITICAL)

Checks whether a file named like a web font actually contains font data. A `.woff2`, `.woff`, `.ttf`, or `.otf` whose bytes are text rather than a font container is a JavaScript loader wearing an asset's name.

**How it works:** Reads the first bytes of each font-extension file found during the project walk and compares them against the magic numbers for every font container format (`wOF2`, `wOFF`, `OTTO`, `ttcf`, `true`, `typ1`, the TrueType `00 01 00 00` header, and the Type 1 variants). If none match, the file is sampled for text: any NUL byte means binary, and at least 95% of the first 512 bytes must be printable ASCII or whitespace. HTML and XML documents are excluded — a site mirrored with `wget`, or a single-page app behind a catch-all route, saves the index page under a missing asset's name, which is genuinely not font data and genuinely not an indicator of anything.

**Why this matters:** This is the check that survives the campaign rotating its constants. PolinRider hides its loader inside `public/fonts/fa-solid-400.woff2` specifically because a `.woff2` reads as binary: reviewers skip it, `grep`-for-IOCs passes report it clean, and diff tools show it as an opaque blob. But whatever generation of the payload is inside, and whatever string constants it uses, the file still has to be JavaScript for `node` to run it — so the extension/content mismatch holds even when every signature in the list below has been rotated out from under us. It is also the cheapest possible check: the first four bytes settle it.

---

## 16. `payload-signature` (CRITICAL)

Checks selected metadata, execution targets and documented injection candidates for published payload indicators. Project membership and source extensions alone do not select file contents. `-broad` expands general content inspection outside projects; `-browser-cache` separately includes browser caches; it is not enabled by default. Dependency content inspection uses the default selection policy in [Scanning behavior](SCANNING.md#routine-content-scope).

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

**How it works:** Published literal signatures also match fixed-width ASCII `\xNN` / `\uNNNN` escapes without evaluating code. Header names and the existing resolver wallet are case-insensitive. For selected candidates (or with `-broad` outside dependencies), supported formats include ordinary JS/CJS/MJS/TS/JSX/TSX, Python, shell, JSON/JSONC settings, YAML/TOML/INI/conf, XML/plist/service, HTML/Vue/Svelte, PHP/Ruby/Dart, text/Markdown, extensionless files, and supported assets; the exact list is `SignatureScannedExtensions` in `internal/scan/ioc.go`. Other extensions remain excluded. General source candidates receive an 8 KiB prefix check before their bodies are read; a NUL or invalid UTF-8 prefix excludes the binary body from text inspection. A UTF-8 character split by the prefix boundary is allowed. Binary/non-UTF-8 content is not searched as general source. Known markers in documentation/test paths produce warnings rather than confirmed-compromise claims; this is not a repository-controlled suppression mechanism. Text candidates below 100 MB are still read in full within a shared five-second read/inspection deadline. Larger inputs and failures produce coverage diagnostics. Recognized asset headers only receive header inspection; archives are not unpacked.

**Why this matters:** PolinRider appends its loader to the end of a real build config after roughly 280 spaces of padding. The file still opens, still builds, and still looks untouched in a diff unless you scroll right — a `tailwind.config.js` that is normally 80–200 bytes becomes ~5,000. Filename matching cannot find this, because the file is supposed to exist and is supposed to have that name. Content matching is the only option. Note that the campaign has already rotated its constants once (the March `rmcej%otb%` / `_$_1e42` pair became `Cot%3t=shtP` / `MDy` in April, an evasion response to OSM's published YARA rule), which is why every generation is listed and why a clean result here is not proof of anything — see the next check.

The wallet and initial fetch-path signatures identify the resolver rather than an obfuscator generation. The markers above identify a *generation of the obfuscator*; the wallet address and the `/0x/…` fetch paths identify the *C2 resolver itself*, which is the part the campaign cannot cheaply change. Every address in the C2 IP list rotates for the price of one Ethereum transaction, because the loader reads the next host off-chain — but the wallet it reads **from** is compiled into the payload, so moving it means republishing to every victim. That makes it the one constant that pins a sample to this campaign rather than to a guess. Two caveats, both real: `bianira-ui` writes identifiers as `\uXXXX` escapes; the scanner now normalizes fixed-width ASCII escapes as well as checking its version pin, and the OSV records that document these constants describe delivery through trojanized npm packages, not the force-pushed repositories the rest of the PolinRider coverage targets. Same resolver and same C2 family, different distribution.

---

## 17. `padded-source-file` (WARN)

Flags a JS-family file, dictionary file, or font-extension file whose contents are text and which contains 200 or more consecutive spaces between non-whitespace text on the same line.

**How it works:** Search for a precomputed space run, then check each matching line with leading and trailing whitespace removed. Applied only to files that already passed the signature scan without matching. If a known signature matched, this check stays quiet — one injection produces one finding, not two.

The text precondition is load-bearing, not a nicety. Pushing a payload off the right edge of an editor viewport is a trick that only means anything in a file a human reads as text; inside a binary container, a run of `0x20` bytes is just data. A 21 MB CJK TrueType font has ample room to contain 200 consecutive spaces in its glyph tables by coincidence, and flagging that is noise. Fonts that really are text are still caught — as a critical `fake-font-payload` finding, by the magic-number check above.

**Why this matters:** This is the deliberate backstop for `payload-signature`. The check requires 200+ spaces between non-whitespace text on the same line, matching the documented off-screen append pattern. Leading indentation and trailing whitespace do not qualify; generated license comments can contain hundreds of leading spaces. Because it describes the *shape* of the injection rather than any particular payload, it keeps working after the campaign rotates its constants — which it has done once already and will do again. It is a warning rather than a critical finding because the shape alone is not proof, and the honest reading of a hit here is "this looks like an injection we do not have a signature for yet."

---

## 18. `malicious-repo-artifact` (CRITICAL)

Checks for known artifact filenames during the home-directory walk rather than at a fixed path. Ambiguous filenames require content verification. Payload hashes with a published exact size are additionally matched under any filename or extension: a file whose length matches a sized entry is hashed, and a SHA-256 match is reported with a note naming the filename the payload was published under.

**Known artifacts:**

| Filename | Description | Source attack |
|----------|-------------|---------------|
| `temp_auto_push.bat` | Propagation script: resets the clock, amends the last commit, force-pushes | PolinRider |
| `config.bat` | Hidden orchestrator (added to `.gitignore` to hide it from `git status`) | PolinRider |
| `*.inz.cjs`, `*.inz.orig` | Implant module dropped beside a patched Electron or npm entrypoint | PolinRider |
| `router_init.js` | Payload loader | Mini Shai-Hulud |
| `tanstack_runner.js` | Bun-loaded payload | Mini Shai-Hulud |
| `Math_Symbol.js` | Second-stage payload, confirmed by SHA-256 `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | keyv npm compromise |
| `fa-solid-400.woff2` | Exact dropper bytes, confirmed by SHA-256 in the active hash list | PolinRider (incident-sourced hash) |

**How it works:** Exact basename match for the named files except the SHA-256-confirmed `Math_Symbol.js` and `fa-solid-400.woff2`; suffix match for the `.inz` modules, because the stem varies with whichever file was patched. A legitimate `build.bat` is not flagged.

`Math_Symbol.js` is also a [legitimate Unicode data filename](https://github.com/mathiasbynens/regenerate-unicode-properties/blob/v10.2.0/General_Category/Math_Symbol.js). Its name selects it for bounded content inspection; this check only reports it when its bytes match the known malicious SHA-256. The file is also checked for other payload signatures and padding. Neither its path nor its size alone establishes compromise. Read failures follow the normal incomplete-scan reporting. This check also runs inside dependency directories by default.

`router_init.js`, `tanstack_runner.js` and `Math_Symbol.js` also appear in the package-scoped `npm-payload-file` check, which remains unchanged and can flag unexpected payload files in known affected packages. The repository checks additionally cover other carriers encountered during the walk. `setup.mjs` stays package-scoped because it is a plausible legitimate filename.

**Why this matters:** `temp_auto_push.bat` is the highest-confidence indicator of past compromise in the entire campaign. PolinRider's propagation runs locally, not from a server: the script resets the machine clock, amends the last commit so the timestamp matches the one it replaced, and force-pushes using whatever git credentials are already cached. Nothing leaves the machine that GitHub can distinguish from the real developer — same device, same SSH key, same behavior GitHub sees every day — which is exactly why the artifact left on disk is the evidence. OSM found it still sitting in 101 victim repositories whose owners had already cleaned the payload out of their config files and believed they were done.

---

## 19. `gitignore-injection` (CRITICAL)

Checks `.gitignore` files for entries an attack added to conceal a file it dropped.

**Known injected entries:**

| Entry | Description | Source attack |
|-------|-------------|---------------|
| `config.bat` | Hides the dropped orchestrator from `git status` | PolinRider |

**How it works:** Reads each `.gitignore` found during the walk and compares every trimmed line against the known-injected list as a whole-line match.

**Why this matters:** This one survives cleanup of the file it was hiding. A developer who finds and deletes `config.bat` has removed the payload but not the evidence that something put it there — and the `.gitignore` line is what kept `git status` quiet while the orchestrator sat in the repo. A `.gitignore` listing a file the developer never created is a deliberate concealment step, and it is worth knowing about even after the file itself is gone.

---

## 20. `patched-npm-cli` (CRITICAL)

Checks the global npm CLI entrypoint (`npm/lib/cli.js`) for signs of having been overwritten.

**How it works:** Glob-matches every install layout surplies supports — system (`/usr/lib`, `/usr/local/lib`), Homebrew (`/opt/homebrew`), MacPorts (`/opt/local`), nvm, fnm, Volta, `n`, `.npm-global`, and the Windows `%APPDATA%\npm` and `%ProgramFiles%\nodejs` paths. Globs rather than `npm root -g` on purpose: multiple Node installs routinely coexist, and asking one of them where it lives reports on that one only. A file over 100 KiB is flagged on size; under that, it is still read and checked against the `payload-signature` list and `.inz.cjs` / `.inz.orig` references, so a small sidecar-loading stub is caught too. Adjacent sidecar files are checked by name, including when the CLI entrypoint has been removed.

**Why this matters:** This is the persistence that outlasts everything else. A poisoned project config only runs when that project builds; a patched `cli.js` re-spawns the payload on *every* `npm`, `npx`, or `npm exec` invocation, survives a reboot, and survives a full credential rotation — one developer traced their reinfection to an editor silently running `npm exec <package>@latest` in the background. The real file is a few hundred bytes across every npm major version (four lines that require the implementation); the PolinRider replacement is roughly 1 MB with the payload appended after a long whitespace run starting on line 5. The 100 KiB threshold sits two orders of magnitude above normal and an order below the malicious size, so the check does not depend on either number staying exact.

---

## 21. `scan-incomplete` (WARN)

Reports general project/persistence traversal errors, failed content reads, read/inspection timeouts, cloud-sync placeholders whose contents are not on local disk, and files rejected by the 100 MB content limit. Missing explicit persistence roots also warn; absent optional default installation paths do not.

**How it works:** Reading and inspecting a selected file together are bounded at 5 seconds. Recognized font and supported asset containers are checked from their first 32 bytes; their bodies are not searched for embedded scripts and their size does not produce a coverage warning. Text disguised as a font still receives content checks. General-source candidates with binary prefixes stop after at most 8 KiB, before full-file allocation or reading. Other selected files, including text candidates and targeted application entrypoints, are read in full below 100 MB (100,000,000 bytes); files at or above that limit are not content-checked and report `size limit exceeded`. Before a selected file is opened, the stat the read already performs is checked for the flag the operating system uses to mark a cloud-sync placeholder — `SF_DATALESS` on macOS, `FILE_ATTRIBUTE_OFFLINE` / `RECALL_ON_OPEN` / `RECALL_ON_DATA_ACCESS` on Windows. A flagged file is skipped unread under the `not downloaded` category and never opened. On macOS, an open or directory listing refused with `resource deadlock avoided` (`EDEADLK`) is the same placeholder reached without the flag, and is reported under `not downloaded` too. Each read that does time out is its own warning naming the file, and the scan keeps a single budget of one minute for the total time lost to such reads across the whole run; spending it stops content reading everywhere, skips the remaining Git phase, and emits one CRITICAL record stating how many files went unread afterwards.

**Why this matters:** Files under Dropbox, OneDrive, iCloud Drive, or Google Drive often exist only as placeholders whose contents live on the provider's servers. Opening one succeeds immediately and fetches nothing; the first *read* is what asks the provider for the bytes. When the provider is offline, the account is unlinked, or the file is gone server-side, that read blocks indefinitely and then fails — and when it is healthy, it quietly downloads the file, which is not something a scan should do to someone's archived storage on its own initiative. The flag answers the question for free, from a stat the walk already made, and is cleared once a file is hydrated, so a file that has been downloaded is read normally.

Skipping a placeholder is a warning because the gap is named and bounded: the record says exactly which file was not read, and making it available offline and re-running covers it. Only files already selected for reading are ever mentioned — a placeholder the scan was never going to open does not appear.

Running out of the stall budget is different in kind, and is a CRITICAL coverage verdict for the same reason as the Git record below: the scan stopped covering the machine and nothing names what it missed. With placeholders recognised by flag, a read that still hangs means something is actually broken — a stalled NFS or SMB mount, a failing disk, a sync client that is running but not serving — and there is no healthy subtree to salvage by guessing which directory is at fault. Twelve timeouts is enough to tell one odd file from a machine that cannot answer, and it makes the worst case statable: a scan never loses more than a minute to hangs, whatever the directory layout. Like every coverage verdict it is never counted as an attack indicator; the summary says coverage failed critically, and the run exits 2.

Coverage limitations appear in a compact, separate summary in text output; they are not counted as attack indicators. The summary counts size-limit failures, permission denials, timeouts, undownloaded placeholders, Git errors, Git coverage, network collection errors, and other errors separately. Coverage failures list paths grouped by category and shared cause: each explanation appears once, followed by sorted affected paths. Routine scope notices are summarized by category, with exact paths retained in JSON. JSON retains each exact error or read limit. JSON retains individual `scan-incomplete` records, and incomplete coverage still produces a nonzero exit status and an explicit qualification in the final result.

One `scan-incomplete` record describes the Git scan as a whole rather than a path, under the `Git coverage` category. A scan that found no repositories at all reports a WARN: no history was inspected, and that must not read as a Git scan that found nothing wrong. A scan that could not complete more than 25% of the repositories it did find reports a CRITICAL, which exits 2 and prints a banner naming the counts. Any run that scanned none of the repositories it found is above that threshold regardless of how few there were — 0 of 2 is not a scan with gaps in it. Individual failures are still listed under `Git errors`; this record only states what they add up to. It is a coverage verdict, not an attack indicator, and is never counted as one: the summary says plainly that coverage failed critically rather than reporting a critical indicator.

## 22. `patched-application` (CRITICAL)

Checks documented VS Code, Cursor, Antigravity, GitHub Desktop, and Discord entrypoints for known payload markers or references to `.inz.cjs` / `.inz.orig`. Application presence, a generic `require()`, and arbitrary date-like comments do not trigger findings.

| Target | Files inspected | Source attack |
|--------|-----------------|---------------|
| VS Code / Cursor / Antigravity | `node_modules/@vscode/deviceid/dist/index.js`; `out/main.js` where present | PolinRider (DPRK / Contagious Interview) |
| GitHub Desktop | `resources/app/main.js` (`Contents/Resources/app/main.js` on macOS) | PolinRider (DPRK / Contagious Interview) |
| Discord | Versioned `modules/discord_desktop_core*/discord_desktop_core/index.js` | PolinRider (DPRK / Contagious Interview) |

The default scan checks these paths independently of the home walk and dependency boundaries. Conventional installation layouts include macOS `/Applications` and `~/Applications`; Windows Program Files, LocalAppData Programs and versioned GitHubDesktop directories; and Linux `/usr/share`, `/usr/lib`, `/opt`, and `~/.local/share`. Discord data directories use macOS Application Support, Windows AppData, or Linux XDG config. Exact discovery patterns are in `ApplicationEntrypointGlobs` in `internal/scan/ioc.go`.

Adjacent `*.inz.cjs` / `*.inz.orig` files produce `malicious-repo-artifact` findings even if the entrypoint is absent. Duplicate discovery of the same path is suppressed. Entry files below 100 MB are fully inspected, including their middle and tail. Files at or above that limit receive a `scan-incomplete` size-limit warning. Reading and inspection share one five-second deadline. Access/read failures also produce `scan-incomplete` warnings. No application or package manager is executed.

Persistence discovery shares the project walk under home and recursively searches `/usr/local/lib`, `/opt`, `/usr/lib`, and `/usr/share` on Unix, plus `/Applications` on macOS; Windows searches home and Program Files. Discovery crosses dependency directories by default and recognizes renamed app bundles and custom npm prefixes. It reads selected entrypoints, not every file's contents. The public [NullReceiver scanner](https://github.com/OsamaCodes62/nullreceiver-ir-kit/blob/main/scan_macos.sh) supplies the recursive sidecar/entrypoint approach; [StepSecurity](https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise) documents the application targets. Search roots are coverage choices, not additional IOCs.

Use `-root /custom/path` (repeatable) to add locations to the full project and Python package scans, including existing content, artifact, and persistence checks. Home and system checks still run. On Windows, home is the user profile and the help text lists the configured Program Files paths for system persistence searches; Unix help uses `~` and its platform-specific system roots. Dependency content selection and targeted persistence checks apply in all roots. Explicit roots expand discovery locations, not permission to read every source/text file. Recognized browser caches still require `-browser-cache` and raw npm stores require `-npm-cache`; this is not an every-file content scan. `.git` directories are excluded from ordinary content traversal; Git history receives the separately documented exact-hash checks by default. Root symlinks are resolved; directory symlinks encountered within a tree are not traversed. Each one whose target leaves every scan root is reported once as a scope notice, so the skipped tree is visible rather than silently absent. Supply their destination as another root when needed. Overlapping recursive roots are deduplicated. ASAR archives are not unpacked. Signature matching normalizes fixed-width ASCII escapes but does not unpack or execute obfuscated code, and absence of a marker does not establish that the host was never compromised.

## 23. `font-execution-task` (CRITICAL)

Checks `.vscode/tasks.json` for a `folderOpen` task that executes a font-extension file with Node.js. This catches the published fake-font task even if the font has been removed and the task contains no payload signature.

JSON comments and trailing commas are accepted. The check supports command strings, quoted command objects, separate string or quoted-object arguments, and Windows/Linux/macOS command overrides. It recognizes direct Node commands and shell command boundaries, including the POSIX/Windows fallback form. It does not emulate a shell or resolve variables and task dependencies. Legitimate automatic watchers, an echoed command, or a font passed to a normal JavaScript conversion script are not findings. `task.allowAutomaticTasks` alone is not an IOC.

Source attack: PolinRider (DPRK / Contagious Interview), from OpenSourceMalware's fake-font/automatic-task reporting and ByteGuard's public task detection.

## 24. `runtime-staging-artifact` (WARN)

Checks `~/.node_modules/node_modules/` and `get-pip.py`, `.pip`, and `.npm` in the OS temporary directory (also `/tmp` and `/var/tmp` on Unix). These paths are documented by the NullReceiver IR kit. Their presence has legitimate explanations, so they are warnings to correlate with payload/persistence findings, never standalone proof of compromise. The user's ordinary `~/.npm` cache is not flagged by this check.

Source attack: PolinRider (DPRK / Contagious Interview).

## 25. `git-payload-hash` (CRITICAL)

Matches blobs against the sized entries in the [active hash list](ATTACKS.md#active-payload-hashes), independent of names and the checked-out branch. Where a published Git object identity exists, the blob's object ID is matched directly with no body read; otherwise a blob whose size matches a sized entry is hashed and verified by raw-content SHA-256. Source attacks: keyv npm compromise and PolinRider (incident-sourced hashes). A hit can be confined to historical commits; inspect the reported object before drawing conclusions about current files or execution. Git collection failures are `scan-incomplete` warnings, not malware findings; when they account for more than 25% of the repositories found, the run-wide coverage verdict is critical.

**Filename-gated history checks.** Size alone reaches only the payloads published with one. A blob whose name the filesystem walk would have opened is also read, and the same identity-based checks run against it: [`malicious-repo-artifact`](#18-malicious-repo-artifact-critical), [`gitignore-injection`](#19-gitignore-injection-critical), [`payload-signature`](#16-payload-signature-critical), [`font-execution-task`](#23-font-execution-task-critical), [`fake-font-payload`](#15-fake-font-payload-critical) and the carved config-append span. Findings name the repository, the historical path and the blob. This is what reaches a repository that was cleaned in the working tree but never had its history rewritten — the ordinary state after a developer deletes the payload and commits the fix, where every working-tree check now passes while the poisoned commit is still on the remote and in every clone.

Object names require [Git 2.50](https://github.com/git/git/blob/master/Documentation/RelNotes/2.50.0.adoc), whose `rev-list -z` emits them NUL-framed. The legacy format joins the object ID and the path with a space on a newline-terminated line, and a path may contain either, so an older Git is given `--no-object-names` and the size-matched half runs alone — reported as [`git-too-old-for-filenames`](#27-git-too-old-for-filenames-critical), never as silent coverage.

**What is deliberately not run against history.** The general heuristics — [`suspicious-source-execution`](#29-suspicious-source-execution-warn), [`unicode-concealment`](#30-unicode-concealment-warn), [`loader-structure`](#31-loader-structure-warn), [`padded-source-file`](#17-padded-source-file-warn) — stay on the working tree. History holds every revision of every file, so one pattern in one file becomes a warning per revision, pointing at a commit nobody is going to edit. Measured against a 49,000-blob repository they produced 305 warnings and no indicator. Only checks that name a specific published payload carry over, because those stay true however many revisions hold them.

**Selection is the filesystem rule, not a broader one.** A history blob is read when its name is one the filesystem walk would open: a payload or artifact filename, `.gitignore`, a `*.config.*` JavaScript file, a documented injectable source name, a font, or a `.vscode`/`.claude` settings file. A source extension never alone selects a blob, exactly as it never alone selects a file on disk. Selecting by extension instead reads every `.py`, `.js` and `.json` ever committed, which on a real machine meant reading a developer's own IOC research scripts out of history and reporting their C2 constants as indicators. Size-matched blobs still need no name, so a renamed dropper stays reachable.

**Repeated hits are rolled up.** A configuration poisoned once is a separate blob in every later revision that kept it. Findings accumulate per repository and print one line per indicator with the revision count, naming the first blob as the one to investigate. JSON keeps the full detail.

Size-less hash entries remain excluded from Git blob *candidates* — a size-less entry must never mean "hash every blob in every repository" — but where such an entry is filename-gated, the filename now reaches history as it does the working tree.

## 26. `git-too-old` (CRITICAL)

Reports an installed Git older than 2.45 when the scan found at least one repository. `git` is resolved from `PATH` only.

**How it works:** Every Git command this scanner runs passes `--no-lazy-fetch`, a top-level option added in [Git 2.45](https://github.com/git/git/blob/master/Documentation/RelNotes/2.45.0.adoc) (`GIT_NO_LAZY_FETCH` landed in the same release and is no substitute). An older Git rejects the whole command line with exit 129 before opening anything, so repository discovery itself fails and not one repository is inspected. A single bare `git --version` — the one command that predates every option used here, and which is never given the hardening flags that would make it fail on exactly the Git it exists to identify — records the resolved path and version on every Git-enabled run, pass or fail. Both appear in `stats` and on a `Git binary:` line in the summary. The critical finding is gated on having found a repository: a machine with no repositories needed no Git and is not failed over one it never called.

**Why it is CRITICAL:** The file half of the scan is unaffected, so the run completes, prints a normal-looking report, and exits 0. A clean result in that state is a files-only verdict with nothing saying so. A scan that is trusted while its supply-chain half never ran is worse than one that fails outright. Like `scan-incomplete`, this describes the scan rather than the machine: it is never counted as an attack indicator, and the summary says coverage failed critically rather than reporting a critical indicator.

**Why `PATH` only:** No fallback hunting for Homebrew or another copy. A fallback would mean a root-context scan executing a binary out of a user-writable directory — `/usr/local/bin` is world-writable by default on macOS — in a tool whose job is finding a local compromise. It is also easy to miss without the recorded path: an interactive shell with Homebrew first resolves a modern Git and scans fine, while a root daemon under a minimal `PATH` resolves Apple's `/usr/bin/git` and reports `0/N` on the same machine in the same minute. On a stock Mac that is decided by the Xcode Command Line Tools: Apple Git-155 is Git 2.50.1 and works; Apple Git-146/154 are Git 2.39.x and fail.

## 27. `git-too-old-for-filenames` (CRITICAL)

Reports an installed Git from 2.45 through 2.49 when the scan found at least one repository. `git` is resolved from `PATH` only, on the same terms as [`git-too-old`](#26-git-too-old-critical).

**How it works:** Reading the name a blob was committed under requires `rev-list -z`, added in [Git 2.50](https://github.com/git/git/blob/master/Documentation/RelNotes/2.50.0.adoc), which frames each record with NUL bytes so a path containing a space or a newline stays unambiguous. Every other command this scanner runs works from 2.45, so a Git in that range completes the scan and inspects every repository — by payload size and published object identity only. The [filename-gated history checks](#25-git-payload-hash-critical) do not run. Working-tree coverage is unaffected.

**Why it is CRITICAL:** The same reason as `git-too-old`, one degree in. The run completes, the repository counts look normal, and nothing in them distinguishes a history scan that ran everything from one that ran half. The half that did not run is the one that reaches the config-append landing, whose carrier is the victim's own build config and therefore has no fixed size to match. Like `git-too-old`, this describes the scan rather than the machine: it is never counted as an attack indicator, and the summary reports a critical coverage failure rather than a critical indicator.

## 28. `scan-limited` (INFO)

Reports expected scope limits, such as shallow Git repositories whose older history is not available locally, or the temp directories a `-skip-tmproots` run did not walk. These notices are grouped by shared explanation in human output and retained individually in JSON. They are not attack indicators or scan failures and do not change the exit status. Actual inspection failures remain `scan-incomplete` warnings.

## 29. `suspicious-source-execution` (WARN)

Flags source that decodes and executes, pipes a download into a shell, or spawns a hidden detached child.

**What it looks for:**

| Pattern | Match |
|---------|-------|
| Decode-and-execute | `eval(` or `Function(` wrapping `Buffer.from`, `atob`, `unescape`, or `decodeURIComponent` |
| Download-to-shell | `curl` or `wget` piped to `sh`, `bash`, or `zsh` on one line, within 200 characters |
| Hidden detached spawn | `spawn(` with both `detached: true` and `windowsHide: true` nearby, in either order |

**How it works:** Fixed-width ASCII escapes (`\uXXXX`, `\xXX`) are decoded to their printable characters first, so an escaped `eval` still matches; nothing is ever evaluated or unpacked. `eval` on its own, a public RPC URL on its own, and an ordinary `spawn` do not qualify — each pattern requires the correlation above.

**Why it is WARN:** These shapes are common in minified bundles, installers and build tooling as well as in malware. A hit says static review is required; it does not establish that anything ran. This is a general source heuristic, so it runs against the working tree only and never against Git history, where one pattern would otherwise become a warning per revision.

## 30. `unicode-concealment` (WARN)

Flags source that hides code from the reader with invisible Unicode, the GlassWorm technique.

**What it looks for:**

| Signal | Match |
|--------|-------|
| Unbalanced bidi controls | `U+202A`/`U+202B`/`U+202D`/`U+202E` or the isolates `U+2066`–`U+2068` left unterminated, or a stray `U+202C`/`U+2069` |
| Variation-selector run | Eight or more consecutive selectors from either range: `U+FE00`–`U+FE0F` and `U+E0100`–`U+E01EF` |
| Concealed joiner | `U+200C` or `U+200D` between two ASCII identifier characters |

**How it works:** Each line is scanned separately, keeping a stack of open bidi controls. Ordinary emoji variation selectors, balanced right-to-left text, private-use glyphs, and joiners between non-ASCII scripts do not qualify. There is no long-line cutoff.

Source attack: [GlassWorm](ATTACKS.md#glassworm-unicode-concealment). Working tree only, for the same reason as `suspicious-source-execution`.

## 31. `loader-structure` (WARN)

Flags an `import.meta.url` expression invoked immediately on a relative `.cjs` sidecar — the published shape of a loader that hands control to a CommonJS module sitting beside it.

**How it works:** Matched on the escape-normalized text, and only in a file that has an `import` in it. Legitimate ESM-to-CJS loaders exist, so the finding names the referenced module for inspection rather than asserting compromise.

## 32. `loader-variant` (WARN)

Flags an assignment to `global['_V']` or `global['!']`, the published injection form, across quoting and spacing variants.

**How it works:** Checked only when the file did not already match a `payload-signature` constant, so one injection produces one finding rather than two. The match is a community-documented form, reported as context to review rather than inheriting the upstream severity.

## 33. `correlated-loader-markers` (WARN)

Flags a community-documented build marker that appears alongside loader or decode/execute structure.

**What it looks for:**

| Marker | Match |
|--------|-------|
| Build tag | `/*C######*/`, `/*M######*/`, or `/*RS######*/`, with an optional trailing letter |
| Named marker | `__inzV` or `app-vscode-eval` |

**How it works:** A marker alone is never a finding — the file must also carry loader structure, the `loader-variant` assignment, or a decode-and-execute call. The `C` series is matched in addition to the `M` and `RS` prefixes ByteGuard publishes, because it is the larger half of the observed markers and a date tag costs the operator nothing to change.

## 34. `escaped-execution` (WARN)

Flags a run of eight or more consecutive `\u00XX` ASCII escapes in a file that also has `eval(`, `Function(`, or loader structure in it.

**How it works:** Matched against the raw bytes, before escape normalization, so what it sees is the concealment itself. Escaping printable ASCII is a way of writing identifiers that reviewers and greps do not read; dynamic execution in the same file is what makes it worth reporting.

## 35. `asset-format-mismatch` (WARN)

Flags a file with a binary asset extension whose bytes do not match the format it claims.

**What it looks for:**

| Extension | Expected header |
|-----------|-----------------|
| `.png` | `89 50 4E 47 0D 0A 1A 0A` |
| `.jpg`, `.jpeg` | `FF D8 FF` |
| `.gif` | `GIF87a` or `GIF89a` |
| `.webp` | `RIFF` with `WEBP` at offset 8 |
| `.ico` | `00 00 01 00` |
| `.wasm` | `00 61 73 6D 01 00 00 00` |
| `.pdf` | `%PDF-` |
| `.zip` | `PK\x03\x04`, `PK\x05\x06`, or `PK\x07\x08` |
| `.mp3` | `ID3`, or an MPEG frame sync |
| `.mp4` | `ftyp` at offset 4 |

**How it works:** Leading NUL and whitespace padding is removed before the check, so a padded prefix does not hide the real header. A file whose remaining bytes are text is reported as a possible disguised script; anything else is reported as an unrecognized or truncated header, which may simply be a corrupt file or an unsupported variant. HTML and XML bodies are excluded, because a failed download saved under the asset's name is the common benign case. Font extensions are handled by the critical [`fake-font-payload`](#15-fake-font-payload-critical) check instead.

**Why it is WARN:** These headers are format hints, not validators, and the formats here are not asserted to be confirmed carriers for any campaign. It is a masquerade check: a file that is not what its name says deserves a look.

## 36. `disguised-file-execution-task` (WARN)

Flags an editor task that runs an interpreter on a binary-named file.

**How it works:** Parses `.vscode/tasks.json` (comments and trailing commas allowed) and evaluates each task, including its `windows`, `linux`, and `osx` overrides. The interpreters recognized are `node`, `python`, `python3`, `sh`, `bash`, `zsh`, `powershell`, `pwsh`, `cmd`, `deno`, and `bun`, with or without a `.exe` suffix and at any path. The target must carry an asset extension from the table above, a font extension, or `.bin`, `.dat`, or `.svg`. Common pass-through arguments (`--`, `--no-warnings`, `-File`, `/c`, `run`) are skipped; an option with unknown arity ends the search rather than being guessed past. Unlike [`font-execution-task`](#23-font-execution-task-critical), this does not require `folderOpen`, so a manually run task is still reported — and the automatic Node-on-font case remains the critical finding rather than this one.

## 37. `workspace-setting-context` (WARN or INFO)

Reports `.vscode/settings.json` preferences that make automatic execution easier, as context rather than as compromise.

**What it looks for:**

| Setting | Reported when |
|---------|---------------|
| `task.allowAutomaticTasks` | `"on"` — automatic tasks are enabled |
| `security.workspace.trust.enabled` | `false` — the workspace requests trust disablement |
| `security.workspace.trust.untrustedFiles` | `"open"` — the workspace requests opening untrusted files |
| `terminal.integrated.automationProfile.{osx,linux,windows}` | present and not `null` — a custom automation profile |

**How it works:** One matching preference is INFO; two or more together are a WARN. Current VS Code accepts `"on"` and `"off"` for `task.allowAutomaticTasks`, not a boolean, so any other value is reported as INFO and no bypass is inferred from it. Trust settings are scoped by the editor's own rules, so what a workspace requests is not necessarily what takes effect — the finding says to review the effective settings, and never claims a trust bypass.

## 38. `startup-content` (WARN)

Flags startup and persistence files that reference documented staging paths or C2 addresses.

**How it works:** Reads shell startup files (`.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`), macOS `LaunchAgents`/`LaunchDaemons`, Linux systemd user units, and the `cron.d`/`cron.{daily,hourly,weekly,monthly}` directories. Shell comments and XML comments are removed first, so a commented-out line is not evidence. A finding requires a reference to `/tmp/get-pip`, `/tmp/.pip`, or `verify-human`; a `.node_modules` path combined with Node execution (`node `, `<string>node</string>`, or `ExecStart=`); or a [known C2 IP](#11-network-ioc-active-connection-critical). Binary plists are not decoded and produce a `scan-limited` notice instead; no plist decoder or external command is invoked. Windows startup registry and scheduled-task enumeration are outside scope.

These are community hunt patterns, not campaign attribution. Correlate a hit with payload evidence.

## 39. `hosts-c2-entry` (WARN)

Flags a system hosts file entry that maps a name to a [known C2 IP](#11-network-ioc-active-connection-critical).

**How it works:** Parses each line, ignores `#` comments, and compares the address field against the indicator list in canonical form. This is configuration evidence, not an active connection: it says something wrote a C2 address into name resolution, which is worth explaining regardless of whether anything is talking to it right now.

## 40. `missing-script-target` (INFO)

Reports a package whose lifecycle script names a file that is not installed.

**How it works:** When a manifest declares a hook (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, `prepack`, `postpack`) that runs a JS/CJS/MJS file, and no such file exists, the absence is recorded as context rather than as a read failure: published tarballs routinely strip build hooks and pruned installs drop install helpers. What makes it worth printing at all is that npm would execute anything later written to that path. Because it fires across dozens of packages on an ordinary machine, the human report prints the explanation once and lists the packages; every individual path stays in `-json` and the saved report. Actual read failures remain `scan-incomplete` warnings.

## 41. `running-payload-process` (CRITICAL)

Flags a running process that is executing a PolinRider carrier right now.

| Evidence | What matches | Source attack |
|----------|--------------|---------------|
| Node running a font | A `node` process whose script argument ends in `.woff2`, `.woff`, `.ttf` or `.otf` — the command the [`font-execution-task`](#23-font-execution-task-critical) plants, now executing | PolinRider (DPRK / Contagious Interview) |
| Sidecar argument | Any process with a `*.inz.cjs` or `*.inz.orig` path on its command line, including `--opt=value` forms | PolinRider (DPRK / Contagious Interview) |
| Running script | The script a `node` process is executing, matched against the [active payload hashes](ATTACKS.md#active-payload-hashes), the [`payload-signature`](#16-payload-signature-critical) list, and the carved config-append span | Whichever attack the matched indicator belongs to |

**How it works:** Command lines are read through the operating system's process interfaces — `/proc` on Linux, `proc_info`/`sysctl` on macOS, the Toolhelp snapshot and `NtQueryInformationProcess` on Windows — so no command is run and no process is signalled or attached to. The Node script is the first argument after Node's own options; `-e`/`-p` programs have no script file. A relative script is resolved against the process's working directory, which macOS and Linux expose to the owning account and Windows does not; an unresolvable script is still checked by name, and a `scan-limited` notice counts those not hashed. The script is read under the same five-second, 100 MB limits as any other content. Glob and regex patterns (a `find` or `grep` looking for sidecars) are not sidecar arguments. Processes owned by other users are unreadable on macOS without root and some are protected on Windows; their number is reported as a `scan-limited` notice. A snapshot that does not include the scanner itself reports `scan-incomplete`. Skipped entirely under `-only`, because the process list describes the machine, not a directory.

**Why this matters:** Every other PolinRider check finds a file that *could* run. This one finds the loader running. It adds no indicator: each rule is an on-disk check applied to what is executing. A sidecar loaded from inside a patched Electron app never appears on a command line, so [`patched-application`](#22-patched-application-critical) remains the check for that case, and a process that is not running at scan time is not seen.
