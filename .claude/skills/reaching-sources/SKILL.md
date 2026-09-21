---
name: reaching-sources
description: Retrieve incident writeups and supply-chain tracker pages for surplies IOC research when the page blocks WebFetch and curl with a 403, or when a hash, version, or exact signature string must be read accurately. Covers the agent-browser workflow, Socket's per-campaign packages.csv endpoint, and why WebFetch output must never be the source for a value that lands in ioc.go. Research tooling only; unrelated to what the scanner itself may execute.
---

# Reaching sources

Research tooling only — this has nothing to do with what the scanner itself may shell out to.

Writeups and tracker pages are often behind Cloudflare, which returns `403` to both `WebFetch` and `curl`. Use **agent-browser** (`preview_open` / `preview_navigate`, then `preview_evaluate`) to reach them. Once a page is open, `preview_evaluate` can also `fetch()` same-origin endpoints the page itself links to, which is how you get machine-readable data instead of prose.

- Socket's `supply-chain-attacks/<campaign>` tracker pages block `WebFetch` but load fine in the browser, and each exposes a full CSV at `/api/public/supply-chain-attacks/<campaign>/packages.csv` — every affected package with ecosystem and version, which is exactly what the version checks need.
- Prefer `preview_evaluate` returning parsed/aggregated values over dumping page text; a 400-row table wastes context as prose and reads cleanly as JSON.
- `WebFetch` summarizes through a small model, so it drops and occasionally garbles hashes, version numbers, and exact signature strings. It is fine for "does this page cover X," but re-read the primary with the browser (or `git clone` the dossier repo) before any hash or version lands in `ioc.go`.
