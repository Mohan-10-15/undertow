# Undertow

A phishing detection tool — web app, and a browser extension for the actual moment you'd use it — that analyzes URLs and email text and explains *why* something looks risky. Validated against a real, independently-labeled dataset with a proper held-out test split, not just reasoned about. Optionally cross-checks links against Google's live Safe Browsing threat list using your own free API key.

**[Try it — open `index.html` in any browser, no install needed](#quick-start)**

## Why this exists, and what to read before trusting it

Phishing isn't a "cybersecurity industry" problem — it's the entry point for most breaches everywhere. Every industry needs employees who can spot a bad link.

**Read [What this would actually take to be industry-level](#what-this-would-actually-take-to-be-industry-level) and the [adversarial check](#adversarial-resistance-the-part-that-matters-most) before presenting this as more than it is.** Both sections exist on purpose, and both are documented in full — including the parts that aren't flattering, and two places earlier in this project's history where I was confidently wrong about my own claims (below).

## Features

- **Link scanner** — structure, brand impersonation (typosquatting via edit-distance, leetspeak substitution), high-risk TLDs
- **Email scanner** — urgency language, generic greetings, requests for passwords/OTPs/card numbers, risky attachments
- **Explained, not just scored** — every flag shows the specific reason, sorted by severity
- **Browser extension** — checks the tab you're actually on ([`extension/`](extension/))
- **Optional live threat-intel check** — your own free Google Safe Browsing API key
- **Validated with a proper held-out test split** — see [Real-world validation](#real-world-validation)
- **Persists everywhere, not just inside Claude** — three-tier fallback (see [Storage](#storage)) so scan history and your saved key actually survive a page reload on a real deployment, not just inside the environment this was built in
- **CSP-hardened** — see the comments in `index.html`'s `<head>` for exactly what's allowed and why
- **CI-enforced** — runs the full suite, plus the extension's suite, on every push

## Quick start

No build step, no dependencies. Open `index.html` in a browser. To deploy for a resume/portfolio: push to GitHub, enable Pages from the repo root. For the extension, see [`extension/README.md`](extension/README.md).

## How the detection works

Weighted heuristic rules — no ML model, works offline. Links: structure (IP-as-domain, subdomains, punycode, length), impersonation (edit-distance to ~45 brands, leetspeak normalization), infrastructure (shorteners, high-risk TLDs). Emails: urgency phrasing, generic greetings, sensitive-info requests, risky attachments. Full rules in `engine.js`, fully commented.

## Real-world validation

**Data:** ~50,000 real, independently-labeled URLs — legitimate (UNB URL-2016 dataset) and verified phishing (PhishTank). Not bundled (unclear redistribution license on the aggregating source); `validation/download-data.sh` re-fetches both from their original public sources.

**Methodology, and a correction to it:** the first pass through this data found the original heuristics performed badly (53.2% false positive rate, 38.1% recall) and diagnosed four concrete bugs from the evidence — a length threshold miscalibrated against the actual data (100 chars, when the *median* legitimate URL was 101), a substring-matching bug (`t.co` false-matching inside `bleacherreport.com`), an `@`-detection bug (flagging `medium.com/@username`), and an iteration-order bug (`icicibank.com` flagged as impersonating `citibank`). Fixed, re-measured: 4.5% FPR, 68.4% precision, 23.4% recall.

**That re-measurement had a real flaw, caught afterward:** the 200-character threshold was picked by looking at percentiles of the *same* legitimate-URL file the "after" numbers were then reported against — train/test contamination. `validate.js` now does a proper 60/40 train/test split (fixed seed, reproducible) and reports metrics **only on the held-out test portion**, which never informed any parameter:

| Metric | Held-out test split |
|---|---|
| False positive rate | 4.5% |
| Precision | 68.4% |
| Recall | 23.2% |
| F1 | 0.346 |

These are within noise of the original (contaminated) numbers — reassuring for the outcome, but the process was still wrong to begin with, and `validate.js` prints both side by side so the size of the effect is visible, not asserted.

**Brand list expansion, validated rather than assumed safe:** added ~20 more global brands (Samsung, Alibaba, HSBC, Revolut, etc.) beyond the original US/India-skewed ~30. Tried "telegram" too — validation caught it colliding with `telegraf.com.ua`, a real Ukrainian news site (*"telegraf"* is just the word "telegraph," one edit away from "telegram," not phishing). Dropped it. This is in the code comments in `engine.js`, not just here, because it's the concrete case for why every future addition needs the same check, not a one-time cleanup.

**What's still unvalidated: the email scanner, entirely.** All of the above is the URL scanner. `analyzeEmail` has never been checked against a real corpus of phishing vs. legitimate email — every claim about it is still reasoning, not measurement, exactly the gap this section exists to close for links. I looked for a suitable public dataset and didn't find one I could fetch and verify the provenance of within this project's constraints; this is a stated gap, not a silently dropped one.

Reproduce all of it: `cd validation && bash download-data.sh && node validate.js`

## Adversarial resistance (the part that matters most)

Precision/recall against a historical dataset says nothing about resistance to an attacker who's read `engine.js` — which anyone can, it's open source. `validation/adversarial-check.js` constructs URLs the way that attacker would: a domain not in the brand list, HTTPS, under every numeric threshold, no flagged keyword combination.

**6 of 7 constructed examples score Low risk — indistinguishable from legitimate.** One uses "hdfc" rather than "hdfcbank" (what's actually in the brand list) and evades the impersonation check entirely on that basis alone. This is not fixable by adding more rules: every rule added is equally readable by the next attacker, who routes around it by construction. That's a property of any published, heuristic, client-side detector, not a bug in this one. The realistic mitigation is the optional Safe Browsing layer — a threat-intel source an attacker can't read the rules of in advance — not more heuristics here.

## Two places I was wrong, for calibration

Confidently-stated claims from earlier review rounds that didn't survive checking:

1. **"No SRI hash on the Google Fonts link" (named as a flaw, then attempted as a fix).** Google Fonts serves different CSS per User-Agent for font-format negotiation, so a fixed integrity hash would match one browser's response and break font loading for everyone else. Not applicable here, not just skipped — see the CSP comment block in `index.html`.
2. **"The extension is Chrome/Chromium-only" (named as a flaw, then "fixed").** Firefox actually implements a `chrome.*` compatibility shim specifically so extensions written this way already work there without changes — the original claim was wrong, not just imprecise. What shipped instead is a smaller, still-real improvement: the promise-based `browser`/`chrome` form (standards-track, works natively on Firefox/Safari, supported by Chrome MV3) instead of relying on Firefox's shim, which MDN explicitly documents as "not part of the WebExtensions standard."

Also checked and *not* found to be a problem despite suspecting it: raw Unicode homograph URLs (Cyrillic "а" in "paypal"). JavaScript's `URL` parser auto-converts to punycode, and the existing punycode check catches it — verified with an actual test, not assumed.

## Storage

Three tiers, in order: `window.storage` (Claude's artifact environment) → `localStorage` (works on any real deployment — GitHub Pages, a local file, anywhere) → in-memory only (if even `localStorage` throws, e.g. Safari private browsing). This matters because the first version of this only had the first tier: it worked perfectly *inside this chat*, and would have silently reset on every page load on the exact deployment this README recommends. `localstorage-fallback-test.js` (12 checks) tests the fallback explicitly, including the broken-localStorage-throws-on-every-call case.

## External check (optional)

Add your own free [Google Safe Browsing API key](https://developers.google.com/safe-browsing/v4/get-started) for a live cross-check. Calls `safebrowsing.googleapis.com` **directly from your browser** — your key is visible in your own network tab, fine for personal use, not how you'd build this for other people. CORS support on that endpoint for arbitrary origins was never confirmed; failures degrade to the heuristic result (tested with a mocked rejected fetch), not verified live. v4 (used here) sunsets around March 2027. Non-commercial use only per Google's terms. A backend-proxy reference implementation (not deploy-tested) is in the code comments of `checkSafeBrowsing()`.

## What this would actually take to be industry-level

- **Recall is 23.2% against real phishing, on a proper held-out split.** That's the detection-quality gap, not a documentation gap.
- **Adversarial resistance is close to zero** — 6/7 constructed evasions succeeded. See above.
- **The email scanner has no real-data validation at all**, unlike the link scanner.
- **Still one threat-intel source, called the architecturally-wrong way for production** — direct browser call, not a fused multi-source backend.
- **No learning loop of its own** — only the optional Safe Browsing layer improves without a code change, and that's Google's data.
- **The extension exists and is unit-tested but never loaded in a real browser by me** — no browser in this sandbox.
- **`npm audit` doesn't run in the environment that built this** (times out, confirmed twice) — dependency vulnerability status is genuinely unknown.
- **No independent security review.** 98 automated self-authored checks catch real bugs — several documented above, found by testing against reality instead of assumptions — but "I tested my own work thoroughly" is a different claim than "someone else checked it," and this project has found new, real issues on every single pass so far, which is itself evidence there are more still there.
- **No ops, no legal/compliance layer.**

## Testing

```
npm install && npm test                    # main app: 79 checks
cd extension && npm install && npm test    # extension: 19 checks
cd validation && bash download-data.sh && node validate.js         # real held-out validation
cd validation && node adversarial-check.js                          # evasion check
cd validation && node diagnose-fp.js                                 # false-positive root-cause tool
```

**98 automated pass/fail checks** across `test.js` (19), `functional-test.js` (20), `storage-test.js` (5), `external-check-test.js` (23), `localstorage-fallback-test.js` (12), `extension/popup-test.js` (19). The validation/adversarial scripts are reporting tools, not pass/fail gates — there's no "correct" number of evasions to target, and turning the adversarial script into a test that must pass would just mean tuning to beat my own known test list, the same overfitting mistake documented above.

## Project structure

```
undertow/
├── index.html, engine.js, test.js, functional-test.js,
│   storage-test.js, external-check-test.js, localstorage-fallback-test.js
├── extension/          Manifest V3, cross-browser (browser/chrome shim), popup-test.js
├── validation/         validate.js (train/test split), diagnose-fp.js,
│                       adversarial-check.js, download-data.sh, data/ (gitignored)
├── .github/workflows/test.yml
├── package.json
└── README.md
```

## For a resume or portfolio

- Built and validated a phishing detection tool with a proper held-out test split against ~50,000 real URLs — including catching and correcting train/test contamination in my own first validation attempt, and documenting the correction rather than quietly fixing it
- Ran an adversarial self-assessment (not just accuracy metrics) and found 6/7 constructed evasions succeeded — framed the finding correctly: not a bug list, a structural property of published heuristic detection, with the actual mitigation (external threat intel) identified
- Fixed a real production gap where a tested, working feature (persistence) silently failed on the actual recommended deployment target, by building a proper three-tier fallback and testing the environment without the mock, not just with it
- Practiced calibration under pressure to overclaim: when asked to "complete the project fully" and hit 8/10, corrected two of my own prior flaw claims after checking them (Google Fonts SRI, Firefox compatibility) rather than let a wrong claim stand uncorrected once it had been said out loud
