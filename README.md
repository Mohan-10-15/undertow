# Undertow

Client-side phishing URL and email signal analyzer. Everything runs in your browser — nothing is sent anywhere by default.

## Features

- **URL Analysis** — detects IP-as-domain, brand impersonation (100+ brands), leetspeak homographs, suspicious TLDs (30+), URL shorteners (19), punycode attacks, non-standard ports, deep paths, hex-encoded hostnames
- **Email Analysis** — urgency language (22 phrases), sensitive data requests (21 phrases), generic greetings (12 phrases), excessive caps/shouting, risky attachments, suspicious embedded URLs
- **Zero Network by Default** — no data leaves your browser unless you opt in
- **Optional Google Safe Browsing** — add your own free API key for live threat intelligence
- **Scan History** — last 20 scans stored locally
- **Browser Extension** — checks the page you're on, right from your toolbar (Chrome, Firefox, Edge)

## Quick Start

Open `index.html` in any browser. No build step, no server, no dependencies.

## Install as Browser Extension

### Chrome / Edge

1. Open `chrome://extensions`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Click the Undertow icon on any page to analyze it

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on...**
3. Select `extension/manifest.json`
4. Click the toolbar icon on any page

## How It Works

Undertow checks the same categories a security analyst looks at first:

| Category | What it checks |
|---|---|
| **Structure** | Raw IP addresses, stacked subdomains, encoded characters, unusual length, non-standard ports, deep paths |
| **Impersonation** | Misspelled or look-alike versions of 100+ known brands, numbers swapped for letters (leetspeak), Levenshtein near-misspelling |
| **Pressure tactics** | Urgency language, generic greetings, requests for passwords, codes, or card numbers, excessive capitalization |
| **Domain reputation** | 30+ high-risk TLDs, 19 URL shorteners, punycode/IDN homograph attacks |

This is a heuristic screening tool — not a guarantee. If you add a Safe Browsing key, that check adds real, continuously-updated threat data. When in doubt, verify through a channel you already trust.

## Testing

```
npm install && npm test
```

## Project Structure

```
undertow/
├── index.html            Single-file web app (self-contained)
├── engine.js             Detection engine (Node.js module for testing)
├── test.js               Unit tests for engine.js
├── functional-test.js    Full UI interaction tests (jsdom)
├── storage-test.js       Storage fallback tests
├── external-check-test.js Safe Browsing integration tests
├── extension/            Manifest V3 browser extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── engine.js         Identical copy of root engine.js
│   └── popup-test.js     Extension popup tests
└── validation/           Dataset validation and adversarial checks
    ├── validate.js       Precision/recall against PhishTank dataset
    ├── adversarial-check.js  Resistance to rule-aware attackers
    └── download-data.sh  Fetches validation datasets
```

## License

MIT
