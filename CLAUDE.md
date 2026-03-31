# surplies

## Design principles

- **Filesystem-only detection.** Never shell out to `npm`, `pip`, `python`, `node`, `kubectl`, `docker`, or any other tool. Multiple versions/installs can coexist (system, Homebrew, pyenv, nvm, etc.) and no single tool gives a complete picture. Scan files on disk instead. The sole exception is `netstat`, used only for live network connection IOC matching where no filesystem equivalent exists across all supported platforms.
- **Report only, never remediate.** surplies is a read-only scanner. It must never delete files, uninstall packages, modify configs, or take any corrective action. Findings are reported; the user decides what to do.
- **No container/orchestrator checks.** Do not inspect Docker images, Kubernetes clusters, or other container runtimes. Scope is the local filesystem rooted at the user's home directory (plus well-known system paths for artifact checks).
- **Cross-platform.** All checks must work on macOS, Linux, and Windows (amd64 and arm64). Use `runtime.GOOS` for platform-specific paths; never assume a single OS.
- **Zero dependencies.** stdlib only. No third-party Go modules.
- **Citation-required IOCs.** Only add checks for attacks that the developer explicitly requests with a linked, referenced source. Never speculatively add IOCs or checks from general knowledge.

## Structure

- `main.go` — CLI entry point, flags, output formatting
- `scanner.go` — orchestration, types, npm checks
- `python.go` — Python/PyPI checks (site-packages, .pth files)
- `ioc.go` — known IOC database (bad versions, phantom packages, C2 indicators, artifact paths)
