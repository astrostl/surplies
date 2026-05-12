# Releasing surplies

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- Go toolchain installed
- `modernize` installed (`go install golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest`)
- Push access to `astrostl/surplies`

## Steps

### 1. Decide the version

Use [semantic versioning](https://semver.org/). For IOC-only additions (new packages/hashes), bump the patch version. For new check types, bump minor.

### 2. Sync the README with changes since the last release

Diff `ioc.go`, `scanner.go`, `python.go`, `composer.go`, and `main.go` against the previous release tag to enumerate everything that needs to be reflected in `README.md`:

```sh
git diff $(git describe --tags --abbrev=0) -- ioc.go scanner.go python.go composer.go main.go
```

For each change, update the matching section of `README.md`:

- **New IOC source / writeup** — update the intro bullet list and the **Acknowledgments** section so every cited researcher is credited.
- **New attack covered** — add an intro bullet, and confirm the "N documented major supply chain attacks" count at the top of the README still matches.
- **New `KnownBadNpmVersions` / `KnownBadPythonVersions` / `KnownBadComposerVersions` entries** — update the corresponding `compromised-*` check table.
- **New `KnownPhantomPackages` entries** — update the `phantom-dependency` table.
- **New `KnownC2Domains` / `KnownC2IPs` entries** — update the `network-ioc-active-connection` table.
- **New `KnownProjectArtifacts` / `KnownNpmPayloadFiles` / `KnownMaliciousPthFiles` / `ArtifactsTmp` entries** — update the corresponding `project-artifact` / `npm-payload-file` / `malicious-pth-file` / `suspicious-temp-file` table.
- **New check function or new `Check:` string** — add a new numbered section under **Checks** and, if it changed scanner phasing, update the **Scan phases** list.

Commit the README updates as part of the release commit in step 4.

### 3. Run the release target

```sh
make release VERSION=v1.2.3
```

This will:
- Verify `gofmt -s` formatting and `LICENSE` file presence (`lint`)
- Cross-compile binaries for all platforms
- Package the macOS binaries into tarballs (`dist/surplies-v1.2.3-darwin-{arm64,amd64}.tar.gz`)
- Compute SHA256 checksums
- Patch `Formula/surplies.rb` in place with the new version, URLs, and SHA256s

### 4. Commit and tag

```sh
git add README.md Formula/surplies.rb
git commit -m "Release v1.2.3"
git tag v1.2.3
git push origin main v1.2.3
```

### 5. Create the GitHub release and upload artifacts

```sh
gh release create v1.2.3 \
  dist/surplies-v1.2.3-darwin-arm64.tar.gz \
  dist/surplies-v1.2.3-darwin-amd64.tar.gz \
  dist/surplies-linux-amd64 \
  dist/surplies-linux-arm64 \
  dist/surplies-windows-amd64.exe \
  dist/surplies-windows-arm64.exe \
  --title "v1.2.3" \
  --notes "Brief description of what changed."
```

### 6. Verify Homebrew

```sh
brew update
brew upgrade surplies
surplies -version
```

If testing from scratch:

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
brew install surplies
surplies -version
```

## What the Makefile targets do

| Target | Description |
|--------|-------------|
| `make fmt` | Formats all Go files with `go fix`, `modernize -fix`, and `gofmt -s -w` |
| `make lint` | Checks `go fix`, `modernize`, and `gofmt -s` compliance, LICENSE presence, and `go vet` |
| `make all` | Cross-compiles all platform binaries into `dist/` |
| `make package-macos` | Tars the macOS binaries into versioned `.tar.gz` files |
| `make checksums` | Runs `shasum -a 256` and writes `dist/checksums.txt` |
| `make update-formula` | Patches `Formula/surplies.rb` with new version and SHA256s |
| `make release` | Runs lint + all of the above and prints next steps |

## How the Homebrew tap works

The formula lives at `Formula/surplies.rb` in the main repo. There is no separate tap repo. Homebrew treats the main repo as a tap when users run:

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
```

Each release must have the macOS tarballs uploaded to GitHub Releases before `brew install` will work — Homebrew downloads directly from the release asset URLs in the formula.
