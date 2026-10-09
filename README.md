# dabbi-audit

Do AI answers mention your brand? Find out.

`dabbi-audit` scans a page the way AI crawlers read it — 6 checks, one score, zero signup. Part of the `@digitaldabbi` toolchain.

## Install

```sh
npm install -g @digitaldabbi/dabbi-audit
```

Requires Node >= 18. Zero dependencies.

## Usage

```sh
dabbi-audit https://yourwebsite.com
```

```
  ✗ llms.txt            No llms.txt found at the site root (status 404).
  ✗ schema.org          No JSON-LD structured data found on this page.
  ✗ question-headings   0 of 4 H2s are phrased as questions (0%).
  ✗ answer-blocks       Checked the first 8 paragraphs — none are 30–80 words.
  ✗ entity-signals      1 of 4 entity signals present (social links (2)).
  ✓ performance         Page fetched in 412 ms; viewport meta present.

  SCORE: 15/100 — INVISIBLE IN AI ANSWERS.

FIXES:
  → llms.txt: Add an /llms.txt file at your site root so AI crawlers can read your content.
  → schema.org: Add FAQ, Organization, or HowTo JSON-LD schema to your page.
  ...
```

Flags:

```sh
dabbi-audit <url> --json        # machine-readable output
dabbi-audit <url> --no-color    # plain output, no ANSI codes
dabbi-audit --help
dabbi-audit --version
```

`--json` prints the full report: url, title, score, verdict, per-check pass/detail/hint, and meta (duration, timestamp).

## The 6 checks

| Check | Weight | What it means |
|---|---|---|
| llms.txt | 20 | The instruction file AI crawlers read first. |
| schema.org | 20 | FAQ + Organization + HowTo/Product — the types models trust. |
| question headings | 15 | Questions get quoted. Statements get skipped. Pass at ≥30% of H2s. |
| answer blocks | 15 | 40–60 word blocks models can lift verbatim. Pass at ≥2. |
| entity signals | 15 | sameAs links, Wikipedia/Wikidata, Organization schema, socials. Pass at ≥2 of 4. |
| performance | 15 | Under 2.5 s fetch + viewport meta. Slow pages get skipped. |

Score bands: **≥80** cited and visible · **≥50** halfway into the answer · **<50** invisible in AI answers.

Same engine as the web auditor at digitaldabbi — the CLI is the same logic, no build step, no account.

## Safety

- Refuses private / loopback / link-local / multicast targets (SSRF guard on every redirect hop).
- 15 s timeout, 2 MB page cap, max 5 redirects.
- Polite user-agent: `DigitalDabbi-Audit-CLI/0.1.0`.

## The toolchain

- `@digitaldabbi/dabbi-audit` — this scanner (open, MIT)
- `@digitaldabbi/llms-txt` — llms.txt generator (planned)
- GitHub Action for CI (planned)
- Hosted mention tracking + white-label API (proprietary)

Don't want to DIY? [Digital Dabbi](https://github.com/strawhatmuse-ops/dabbi-audit) does done-for-you audits.

## License

MIT. See LICENSE.
