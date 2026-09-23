# Attacks covered

Full detail on every campaign surplies has indicators for. The README carries the
one-line summaries; source credit for each indicator is in [Attribution](ATTRIBUTION.md).

## [GlassWorm Unicode concealment](https://www.endorlabs.com/reports/invisible-threats-glassworm-unicode-vscode)

Contextual source warnings for long variation-selector sequences and related Unicode concealment. These warnings do not attribute a file to GlassWorm or PolinRider.

## [axios npm compromise](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

Compromised maintainer account published `axios@1.14.1` and `axios@0.30.4` with a phantom dependency (`plain-crypto-js`) that deployed a cross-platform RAT

## [litellm PyPI compromise](https://www.stepsecurity.io/blog/litellm-credential-stealer-hidden-in-pypi-wheel)

Malicious `litellm@1.82.7` and `1.82.8` harvested credentials (SSH, AWS, GCP, Azure, env files) and installed a persistent C2 backdoor via systemd

## [TrapDoor crypto-stealer campaign](https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates)

*Attributed to GitHub actor `ddjidd564`, campaign marker `P-2024-001`, May 2026.*

34 purpose-built phantom packages across npm (21), PyPI (7), and Crates.io (6) impersonating crypto / DeFi / AI developer tooling. npm packages drop `trap-core.js` (48 KB, XOR-encrypted with key `cargo-build-helper-2026`) via `postinstall`, which writes `.cursorrules` and `CLAUDE.md` into the project directory for AI-assistant-driven persistence and pulls runtime config from `ddjidd564.github.io/defi-security-best-practices/`. surplies covers the npm and PyPI phantoms; Crates.io is out of scope (no Cargo scanner today).

## [Mini Shai-Hulud campaign](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)

*Attributed to TeamPCP, April–May 2026.*

An ongoing self-spreading credential-theft worm across npm, PyPI, and Composer. The bulk of the campaign uses compromised maintainer accounts with "double-tap" publishing across `@uipath/*`, `@squawk/*`, `@tallyui/*`, `@mistralai/*`, `safe-action`, `@cap-js/*`, `intercom-client`, PyPI `lightning`/`guardrails-ai`/`mistralai`, Composer `intercom/intercom-php`, and many more. On May 11 a distinct sub-incident hit 42 `@tanstack/*` packages (84 versions) via a different initial-access vector: a fork PR poisoned a GitHub Actions cache, then an attacker-controlled binary extracted an OIDC token from runner memory and published directly to npm — same campaign payload family (`router_init.js`, Session-network exfil via `filev2.getsession.org` / `seed{1,2,3}.getsession.org`, self-propagation), different door in. On May 19 the campaign struck again with the AntV maintainer compromise: 317 packages across `@antv/*`, `@lint-md/*`, and AntV-adjacent unscoped (`echarts-for-react`, `timeago.js`, `size-sensor`, and the rest of the visualization-ecosystem surface) published with the same "double-tap" pattern, a new `@antv/setup` phantom pulled from `github:antvis/G2#<imposter-commit-sha>`, a new C2 endpoint (`t.m-kosche.com`, disguised as OpenTelemetry traces), and a new kitty-monitor persistence variant (`~/.local/share/kitty/cat.py` + `kitty-monitor.{service,plist}`) — same Mini Shai-Hulud toolkit (Bun runtime, hex obfuscation, `firedalazer` GitHub dead-drop trigger, Dune-themed exfil repo naming) per SafeDep's writeup. On June 1 the campaign hit 31 `@redhat-cloud-services/*` packages, published after an attacker minted an npm token from a GitHub Actions OIDC credential stolen from the `RedHatInsights/javascript-clients` repo — same payload family (`preinstall` → `node index.js` → encrypted Bun loader harvesting GitHub Actions secrets, npm tokens, cloud/Kubernetes/Vault material, and SSH/Git credentials). Notably, this wave exfiltrates over a legitimate, non-actor-owned endpoint rather than dedicated C2 infrastructure, so no new network IOC is added; per Socket's writeup.

## [keyv npm compromise](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)

*August 4, 2026.*

Compromised release path for maintainer `jaredwray` published 11 malicious releases across `keyv@6.0.0`, `@cacheable/*`, `cacheable`, `flat-cache`, `cacheable-request`, `file-entry-cache`, `cache-manager`, and `ecto@5.0.1`. Each tarball adds `"preinstall": "node setup.mjs"` plus two payload files (`setup.mjs` 29,918 bytes; `Math_Symbol.js` 727,680 bytes, byte-identical across all affected releases). A second execution path injected Claude Code `SessionStart` and VS Code `folderOpen` hooks (`.claude/setup.mjs`, `.claude/math_init.js`, `.vscode/setup.mjs`) into the keyv repository. The malicious `keyv@6.0.0` release carried valid npm trusted provenance signed by GitHub Actions.

## [PolinRider campaign](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)

*North Korea / DPRK, part of the Contagious Interview cluster; ongoing since December 2025.*

A worm that spreads through developers rather than through a registry. It appends an obfuscated JavaScript loader to a real build config after ~280 spaces of padding, so the file still builds and still looks untouched in a diff; hides the same loader inside files named like web fonts, most often `public/fonts/fa-solid-400.woff2`, which reviewers and scanners skip as binary; and auto-executes via a `.vscode/tasks.json` task with `"runOn": "folderOpen"` the moment the project is opened in VS Code or Cursor. Once resident it harvests credentials, then propagates locally — `temp_auto_push.bat` resets the clock, amends the last commit so the timestamp matches the one it replaced, and force-pushes with cached git credentials, so GitHub sees the real developer. That reaches npm, Packagist, Go, and PyPI through whatever the victim maintains. Confirmed footprint is 4,367 repositories across 2,152 owners. The loader resolves its C2 off the Ethereum blockchain (the NullReceiver technique: the IP is encoded in the destination address bytes of a zero-value transaction), so there is no domain or host to seize. It also overwrites the global `npm/lib/cli.js` with a ~1 MB malicious CLI, which re-spawns the payload on every `npm` invocation and survives reboots and credential rotation, and patches Electron editors themselves — `@vscode/deviceid/dist/index.js` under VS Code, Cursor, and Antigravity, and GitHub Desktop's `main.js`, each rewritten to load a `*.inz.cjs` sidecar. Surplies checks documented application entrypoints and adjacent sidecars in conventional system and user installations, including `/Applications` on macOS, by default. It also checks Discord desktop core and small npm loader stubs. A default scan also reads running command lines for Node executing a font-extension file, an `*.inz.cjs` sidecar argument, or a running script that matches the payload hashes and signatures. Custom installations and archived application code are not exhaustively covered; a clean scan is not proof that a host was never compromised.

## Active payload hashes

The same `KnownRepoPayloadHashes` table drives filesystem and Git checks, in two tiers decided by whether the source published an exact byte size. A filename or file size alone is not malicious; every match is confirmed by SHA-256.

- **Sized entries** are matched under *any* filename or extension. The size is only a cheap candidate filter — a file whose length matches exactly is hashed, and only the digest decides. This catches a payload saved as `dropper.quarantine`, `notes.txt`, or with no extension at all. When a match is reported under a different name, the finding says so and names the published filename.
- **Size-less entries** are matched by their published filename only, and are deliberately excluded from Git blob candidates. Without a size there is no cheap filter, and treating them otherwise would mean hashing every blob in every repository.

Where a source publishes a Git object identity, the blob's object ID is compared directly, with no body read at all, at any size.

| Payload | Raw-file SHA-256 | Exact bytes | Source |
|---|---|---:|---|
| keyv `Math_Symbol.js` | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | 727,680 | [Snyk keyv analysis](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/) |
| PolinRider Fake Font `fa-solid-400.woff2` | `11570a86f8a19cd20bc5e1df112f43c52bc939f18b51c37e902d312fd62f6d27` | 37,566 | Incident-sourced; verified 2026-09-19 |
| PolinRider config-append payload | `85d1294bd225c6fdf938bdc2e2cab392140ac97baccd25442d8c2a0cb015b57d` | 8,626 | Incident-sourced; verified 2026-09-20 |
| PolinRider config-append injected segment | `a2bb666327ef2345871e42d6f354123f16bfbdfe16e5a928dd5afd8c144b7138` | 9,133 | Incident-sourced; the payload behind its 507-space prefix, verified 2026-09-20 |
| PolinRider `tailwind.config.js` | `7d47c430e6e404dc2fa8b4837678d1cbdb4d0aeacec9b405655cab79d54a2ad9` | not published | [Socket PolinRider GitHub/Packagist](https://socket.dev/blog/polinrider-github-packagist) |
| PolinRider `tailwind.config.js` | `b7ede935d4979146b55f12b9eec7c83b61962b478f5dc9b8db251e539ec2abd3` | not published | [Socket PolinRider GitHub/Packagist](https://socket.dev/blog/polinrider-github-packagist) |
| PolinRider `tailwind.config.js` | `ccb187dc9de0cc7477c9817ae53365d273e121407c0305f863e2ab67c35d6395` | not published | [Socket PolinRider GitHub/Packagist](https://socket.dev/blog/polinrider-github-packagist) |
| PolinRider `tailwind.config.js` | `139ea03dcddf4aa810d55740be3cf6c92ce7a9f3cbcbbb35440e25b769a87683` | not published | [Socket PolinRider GitHub/Packagist](https://socket.dev/blog/polinrider-github-packagist) |
| PolinRider `tailwind.config.js` | `515a53291d25d229e1f9fa72e66407e1cfd7e77c91478400b24d5185af68531a` | not published | [Socket PolinRider GitHub/Packagist](https://socket.dev/blog/polinrider-github-packagist) |

The Fake Font dropper's corresponding SHA-1 Git blob identity is `9b2e3a349e377ba2985c593cb3e619f84a0ea1dc`. Git object IDs include an object header and are distinct from raw-file hashes.

The three incident-sourced hashes above are not drawn from a public writeup, and the payloads are not distributed with Surplies. No independent public report of these exact sample hashes was found, which is the norm for this campaign rather than a mark against them — neither the [NullReceiver IR kit](https://github.com/OsamaCodes62/nullreceiver-ir-kit) nor [ByteGuard](https://github.com/n0m4dz/ByteGuard) publishes a single SHA-256, because the payload varies per victim and defenders match strings instead. These additions are not a new campaign; the landings they belong to are publicly documented, and the hashes are additional evidence within them.

**The two config-append hashes describe a span inside a file, not a file.** That variant appends its payload to the last line of a build config the project already loads, so the carrier is the victim's own config and its file hash is unique per victim. Surplies carves the span out of the padded line and hashes that; the 8,626-byte entry is the payload alone and the 9,133-byte entry is the payload behind the injector's constant 507-space prefix.
