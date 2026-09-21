---
name: citation-hygiene
description: Keep IOC citations in sync across ioc.go and the README when adding, revising, or removing an IOC in surplies. Covers which of the four documentation locations must be updated, which outlets may be cited at all, when two incidents count as one campaign, and the Markdown link conventions the README depends on. Use before or while editing ioc.go, or when editing the README's attack list, docs/ATTACKS.md, docs/ATTRIBUTION.md, or the check tables in docs/CHECKS.md.
---

# Citation hygiene

When adding or revising IOCs, keep these four places in sync. They drift independently and the drift is invisible until someone reads the README end-to-end.

1. **`ioc.go` block comments** — each IOC block names its specific writeup(s) with a working URL. If multiple sources contributed (e.g., StepSecurity for the campaign, Aikido for a hash, Socket for broader package coverage), name each one.
2. **README "What it detects"** — the `"Currently detects indicators from N documented major supply chain attacks, sourced from incident writeups by ..."` line, whose comma-separated source list and attack count both need to match reality, plus the one-line summary bullet. The bullet links to the matching `## ` section in `docs/ATTACKS.md`, which carries the full campaign paragraph and the writeup link in its heading.
3. **`docs/ATTRIBUTION.md`** — both the "Sources, in rough order..." bullet list AND the per-writeup bulleted list under it must reflect every source actually used.
4. **`docs/CHECKS.md` check tables** — the "Source attack" column on every affected table (`phantom-dependency`, `compromised-version`, `npm-payload-file`, `network-ioc-active-connection`, `project-artifact`, `compromised-python-version`, `compromised-composer-version`) must use the same campaign name the `ioc.go` comments use.

Other rules:

- **Only cite sources we actually pull IOCs from.** Outlets like Wiz, Snyk, Hacker News, Infosecurity Magazine may be useful in chat for confirming attribution, but they don't go in the README unless we used them for a specific IOC.
- **Sub-incidents are not separate attacks.** Same actor + same payload family + same exfil infrastructure = same campaign, even if the initial-access vector differs. Defer to how Socket / StepSecurity / the campaign's primary trackers frame it; don't infer "distinct attack" from a postmortem that doesn't name the campaign.
- **Attack-bullet style in the intro: one link in the title, no inline citations.** The README bullet is one line linking to its `docs/ATTACKS.md` section; that section's heading carries the single writeup link. `docs/ATTRIBUTION.md` carries the full source credit. Inline links scattered through a paragraph read as "random citations."
- **Code spans inside link text break the underline on GitHub** and make a single link render as multiple visually-disconnected chunks. Move code spans outside the link text, or shorten the link to a trailing `([postmortem](url))` pointer.
