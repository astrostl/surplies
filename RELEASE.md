# Releasing surplies

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- Go toolchain installed
- Push access to `astrostl/surplies`

## Steps

### 1. Decide the version

Use [semantic versioning](https://semver.org/). For IOC-only additions (new packages/hashes), bump the patch version. For new check types, bump minor.

### 2. Run the release target

```sh
make release VERSION=v1.2.3
```

This will:
- Verify `gofmt -s` formatting and `LICENSE` file presence (`lint`)
- Cross-compile binaries for all platforms
- Package the macOS binaries into tarballs (`dist/surplies-v1.2.3-darwin-{arm64,amd64}.tar.gz`)
- Compute SHA256 checksums
- Patch `Formula/surplies.rb` in place with the new version, URLs, and SHA256s

### 3. Commit and tag

```sh
git add Formula/surplies.rb
git commit -m "Release v1.2.3"
git tag v1.2.3
git push origin main v1.2.3
```

### 4. Create the GitHub release and upload artifacts

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

### 5. Verify Homebrew

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
| `make fmt` | Formats all Go files with `gofmt -s -w` |
| `make lint` | Checks `gofmt -s` compliance, LICENSE presence, and `go vet` |
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
