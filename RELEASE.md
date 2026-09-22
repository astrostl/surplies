# Releasing surplies

## Rule zero: `main` is the Homebrew tap

There is no separate tap repo. `brew tap astrostl/surplies` clones **this repo**,
and `brew update` **rebases that clone onto `origin/main`**. The consequence:

> Once a commit is pushed to `main`, it is published. Never `--amend`, `rebase`,
> `reset`, or force-push `main`. Fix forward with a new commit, always.

A force-push does not just inconvenience the next `git pull`. Every tap that
already cloned the old commit keeps it as a local commit on its `main`. From then
on, *every* `brew update` replays that orphan onto the new `origin/main`, it
conflicts on `Formula/surplies.rb`, and Homebrew writes `<<<<<<<` / `=======` /
`>>>>>>>` markers into the live formula. The formula stops being valid Ruby, so
`brew update`, `brew upgrade`, `brew install` and `brew info` all fail with a
parser dump — for that user, forever, on every single invocation, until they
untap and retap. Nothing you push later repairs it.

This has already happened once. On 2026-09-19, `Release v0.9.1` was pushed as
`900f7c1`, amended (the amend touched `Formula/surplies.rb`), and force-pushed as
`d3bd328`. Both commits share the same parent and the same timestamp and differ
only in tree. `900f7c1` is still resolvable on GitHub and is still sitting on
every tap clone made before the amend.

So: get the release commit right *before* pushing it. `git status` must be clean
and `Formula/surplies.rb` must already be correct at commit time, because after
the push there is no taking it back.

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- Go toolchain installed
- `modernize` installed (`go install golang.org/x/tools/go/analysis/passes/modernize/cmd/modernize@latest`)
- `gocyclo` installed (`go install github.com/fzipp/gocyclo/cmd/gocyclo@latest`) — `make lint` enforces `gocyclo -over 15` to match the threshold Go Report Card uses; a release must not introduce any function over 15
- Push access to `astrostl/surplies`

## Steps

### 1. Decide the version

Use [semantic versioning](https://semver.org/). For IOC-only additions (new packages/hashes), bump the patch version. For new check types, bump minor.

### 2. Sync the documentation with changes since the last release

Diff the scanner package against the previous release tag to enumerate everything that needs to be reflected in `README.md` and `docs/`:

```sh
git diff $(git describe --tags --abbrev=0) -- internal/scan main.go
```

For each change, update the matching section:

- **Every release** — point the README's **Install** prebuilt-binary link at the new tag (`https://github.com/astrostl/surplies/releases/tag/vX.Y.Z`); it is a fixed tag URL, so it goes stale silently.
- **New IOC source / writeup** — update the README's "What it detects" list, the matching section of `docs/ATTACKS.md`, and `docs/ATTRIBUTION.md` so every cited researcher is credited.
- **New attack covered** — add a one-line README bullet plus a `## ` section in `docs/ATTACKS.md`, and confirm the "N documented major supply chain attacks" count in the README still matches.
- **New `KnownBadNpmVersions` / `KnownBadPythonVersions` / `KnownBadComposerVersions` entries** — update the corresponding `compromised-*` check table in `docs/CHECKS.md`.
- **New `KnownPhantomPackages` entries** — update the `phantom-dependency` table in `docs/CHECKS.md`.
- **New `KnownC2Domains` / `KnownC2IPs` entries** — update the `network-ioc-active-connection` table in `docs/CHECKS.md`.
- **New `KnownProjectArtifacts` / `KnownNpmPayloadFiles` / `KnownMaliciousPthFiles` / `ArtifactsTmp` entries** — update the corresponding `project-artifact` / `npm-payload-file` / `malicious-pth-file` / `suspicious-temp-file` table in `docs/CHECKS.md`.
- **New check function or new `Check:` string** — add a new numbered section to `docs/CHECKS.md`, a row to the README check table, and, if it changed scanner phasing, update the **Scan phases** list in `docs/SCANNING.md` and the summary in the README's **How it works**.

Commit the documentation updates as part of the release commit in step 4.

### 2b. Audit every Markdown file for accuracy, then get the developer's sign-off

The list above is change-driven: it catches what this release added. It does not
catch what an earlier release quietly made untrue. Documentation rots in one
direction — the code moves and the prose stays — and none of it is covered by
`make lint` or the test suite, so nothing fails when it goes wrong. A reader
deciding whether this tool covers their machine is reading the prose, not the
source.

Read every Markdown file in the repository against the current code, not against
memory of it:

```sh
git ls-files '*.md'
```

That is `README.md`, `CLAUDE.md`, this file, everything under `docs/`, plus
`scripts/README.md` and the skill definitions under `.claude/skills/`. The last
two are easy to forget and no less wrong when stale — a skill file is an
instruction future work is written against, the same as `CLAUDE.md`.

For each, verify:

- **Counts and totals.** "all N checks", "N documented major supply chain
  attacks", any other number written as a word in prose. These drift silently
  and are the most common stale claim.
- **Every documented check still exists, and every check is documented.** Diff
  the `Check:` strings in `internal/scan` against the numbered sections in
  `docs/CHECKS.md` and the README's check table, in both directions. A check
  that fires in a real scan with no section is a gap in a table that claims to
  be complete.
- **Version and threshold claims.** Required tool versions, size and time
  limits, percentage thresholds. Confirm each against the constant it describes.
- **Internal anchors resolve.** Every `docs/CHECKS.md#n-name-severity` link
  breaks the moment a section is renumbered, and Markdown links fail silently.
  Check them with the script below rather than by eye.
- **`CLAUDE.md` still describes the code it constrains.** It is the one file no
  user reads and every future change is written against, so a stale rule there
  causes the next wrong change rather than one wrong impression.
- **Sample output matches what the binary prints.** Summary lines and example
  reports go stale whenever a counter or banner is reworded.

Run from the repository root:

```sh
python3 - <<'EOF'
import glob, re
heads = {re.sub(r'[^a-z0-9 -]', '', h.lower()).replace(' ', '-')
         for h in re.findall(r'^## (.+)$', open('docs/CHECKS.md').read(), re.M)}
for f in glob.glob('docs/*.md') + ['README.md', 'CLAUDE.md']:
    for a in re.findall(r'CHECKS\.md#([a-z0-9-]+)', open(f).read()):
        if a not in heads:
            print('BROKEN', f, a)
EOF
```

**Then stop and ask the developer to confirm.** Show what changed and what you
verified as still accurate, and wait for an explicit yes before continuing to
step 3. Do not fold a documentation rewrite into a release commit on your own
judgment: the developer is the only one who knows whether a rewording is a
correction or a change in meaning, and [Rule zero](#rule-zero-main-is-the-homebrew-tap)
means the answer cannot be revised after the push.

### 3. Smoke-test detection end-to-end

Confirm that the binary you're about to ship actually detects a known bad version, and that it stops detecting it once the fixture is removed. This catches the class of bug where a refactor silently breaks the npm or Python scanner phase.

```sh
make build
make fp
./surplies 2>&1 | grep -E "axios@1\.14\.1|litellm==1\.82\.7"
# expect TWO matching lines — one compromised-version, one compromised-python-version

make fpclean
./surplies 2>&1 | grep -E "axios@1\.14\.1|litellm==1\.82\.7"
# expect NO output — the fixture findings are gone
```

If the first run misses either fixture, do not proceed — the corresponding scanner phase is broken. If the second run still matches, `make fpclean` didn't clean up; investigate before tagging.

Filtering by `grep` (rather than checking exit code) keeps the test honest if the home dir already has unrelated findings.

### 4. Run the release target

```sh
make release VERSION=v1.2.3
```

This will:
- Verify `gofmt -s` formatting, `gocyclo -over 15` (Go Report Card's threshold), and `LICENSE` file presence (`lint`)
- Cross-compile binaries for all platforms
- Package the macOS binaries into tarballs (`dist/surplies-v1.2.3-darwin-{arm64,amd64}.tar.gz`)
- Compute SHA256 checksums
- Patch `Formula/surplies.rb` in place with the new version, URLs, and SHA256s

### 5. Commit and tag

Stage, commit, then **review the commit before pushing it**. This is the last
moment a mistake is cheap; see [Rule zero](#rule-zero-main-is-the-homebrew-tap).

```sh
git add README.md docs Formula/surplies.rb
git commit -m "Release v1.2.3"

git status --short          # must be empty
git show --stat HEAD        # must include Formula/surplies.rb
ruby -c Formula/surplies.rb # must print "Syntax OK"
grep -c v1.2.3 Formula/surplies.rb  # must print 3 (version + two URLs)
```

If any of those is wrong, amend **now**, while the commit is still local. Once
the next command runs, amending is off the table permanently.

```sh
git tag v1.2.3
git push origin main v1.2.3
```

If you discover a problem after this push, fix it with a *new* commit and a new
patch release. Do not force-push `main` to tidy it up — that is precisely the
action that bricks every existing tap.

### 6. Create the GitHub release and upload artifacts

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

### 7. Verify the tap, then upgrade the local Homebrew installation

Two separate things have to be true, and only the first one catches the failure
mode in Rule zero.

**7a. The tap must rebase cleanly.** `brew update` rebases the tap clone onto
`origin/main`. Prove that it did, rather than assuming it:

```sh
brew update
TAP=$(brew --repository astrostl/surplies)
git -C "$TAP" status --short          # must be empty — no U/AA entries
git -C "$TAP" rev-parse HEAD          # must equal the v1.2.3 tag commit
grep -c '^<<<<<<<\|^=======\|^>>>>>>>' "$TAP/Formula/surplies.rb"  # must print 0
```

A non-empty `status`, a mismatched HEAD, or any conflict marker means the tap
carries a commit `origin/main` no longer has. Do not paper over it — find out
what rewrote history, because every other user's tap is in the same state.

**7b. The installed binary must report the new version.** Run the
Homebrew-installed `surplies`, not `./surplies` from the checkout.

```sh
brew upgrade surplies
/opt/homebrew/bin/surplies -version
```

Confirm the reported version matches the release tag. If the upgrade fails or
still reports the previous version, resolve it before declaring the release
complete.

If testing from scratch:

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
brew trust --formula astrostl/surplies/surplies
brew install surplies
surplies -version
```

## If a tap is already broken

Symptom: any `brew` command dumps a Ruby parse error naming
`Formula/surplies.rb`, with `unexpected <<, ignoring it` / `unexpected '='` /
`unexpected >>`, often alongside `Warning: Some taps are not on the default git
origin branch`. The formula on GitHub is fine; the *local clone* has conflict
markers in it.

Nothing pushed to `main` can fix this. The user has to discard the poisoned
clone:

```sh
brew untap astrostl/surplies
brew tap astrostl/surplies https://github.com/astrostl/surplies
brew update
```

`brew untap` removes only the tap clone under
`$(brew --repository astrostl/surplies)`; it does not uninstall the binary.

## What the Makefile targets do

| Target | Description |
|--------|-------------|
| `make help` | Print available targets (default goal — runs when you type just `make`) |
| `make build` | Build `./surplies` for the current platform with version stamping |
| `make fmt` | Formats all Go files with `go fix`, `modernize -fix`, and `gofmt -s -w` |
| `make lint` | Checks `go fix`, `modernize`, and `gofmt -s` compliance, LICENSE presence, and `go vet` |
| `make test` | Runs `go test ./...` |
| `make all` | Cross-compiles all platform binaries into `dist/` |
| `make package-macos` | Tars the macOS binaries into versioned `.tar.gz` files |
| `make checksums` | Runs `shasum -a 256` and writes `dist/checksums.txt` |
| `make update-formula` | Patches `Formula/surplies.rb` with new version and SHA256s |
| `make release` | Runs lint + all of the above and prints next steps |
| `make fp` | Drops `node_modules/axios/package.json` (axios@1.14.1) and `site-packages/litellm-1.82.7.dist-info/` to exercise the npm + Python compromised-version checks |
| `make fpclean` | Removes the fixtures created by `make fp` |
| `make clean` | Removes `./surplies` and `./dist` |

## How the Homebrew tap works

The formula lives at `Formula/surplies.rb` in the main repo. There is no separate tap repo. Homebrew treats the main repo as a tap when users run:

```sh
brew tap astrostl/surplies https://github.com/astrostl/surplies
```

Each release must have the macOS tarballs uploaded to GitHub Releases before `brew install` will work — Homebrew downloads directly from the release asset URLs in the formula.
