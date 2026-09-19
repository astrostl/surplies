---
name: citation-hygiene
description: Keep IOC citations in sync across ioc.go and the README when adding, revising, or removing an IOC in surplies. Covers which of the four README locations must be updated, which outlets may be cited at all, when two incidents count as one campaign, and the Markdown link conventions the README depends on. Use before or while editing ioc.go, or when editing the README's attack list, Acknowledgments, or check tables.
---

# Citation hygiene

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
