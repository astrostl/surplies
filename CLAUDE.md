# surplies

## Design principles

- **Filesystem-only detection.** Never shell out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any other tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scan files on disk instead. The sole exception is `netstat`, used only for live network connection IOC matching where no filesystem equivalent exists across all supported platforms.
- **Report only, never remediate.** surplies is a read-only scanner. It must never delete files, uninstall packages, modify configs, or take any corrective action. Findings are reported; the user decides what to do.
- **No container/orchestrator checks.** Do not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem rooted at the user's home directory (plus well-known system paths for artifact checks).
- **Cross-platform.** All checks must work on macOS, Linux, and Windows (amd64 and arm64). Use `runtime.GOOS` for platform-specific paths; never assume a single OS.
- **Zero dependencies.** stdlib only. No third-party Go modules.
- **Citation-required IOCs.** Only add checks for attacks that the developer explicitly requests with a linked, referenced source. Never speculatively add IOCs or checks from general knowledge.

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

## Structure

- `main.go` — CLI entry point, flags, output formatting
- `scanner.go` — orchestration, types, npm checks
- `python.go` — Python/PyPI checks (site-packages, .pth files)
- `composer.go` — Composer/Packagist checks (vendor/composer/installed.json)
- `ioc.go` — known IOC database (bad versions, phantom packages, C2 indicators, artifact paths)
