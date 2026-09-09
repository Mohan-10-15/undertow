# Undertow browser extension

A Manifest V3 extension that checks the page you're currently on — the form factor the main [README](../README.md#what-this-would-actually-take-to-be-industry-level) names as the actual right one, instead of a page you copy-paste a link into.

It reuses `engine.js` completely unmodified (literally the same file, copied — see below) — no forked copy of the detection logic to drift out of sync.

## Cross-browser

Uses the promise-based `browser`/`chrome` form (`typeof browser !== 'undefined' ? browser : chrome`), which works natively on Firefox/Safari and is supported by Chrome MV3. An earlier version of this project's own review called the callback-based `chrome.tabs.query` form "Chrome-only" — that claim was wrong: Firefox implements a `chrome.*` compatibility shim specifically so extensions written that way already work there. The switch to the promise form is a smaller, still-real improvement (standards-track instead of relying on a shim MDN documents as "not part of the WebExtensions standard"), not a fix for a bug that existed as originally described.

## What's tested vs. what isn't

`popup-test.js` (19 checks) loads the real `popup.html` and `popup.js` into a simulated DOM and drives them with a **mocked** extension API — both the `chrome` and `browser` namespaces, the suspicious-tab path, the clean-tab path, a non-http tab, a missing tab, a rejected query, the manual-check fallback, and no extension API present at all.

**What that does not cover: an actual browser.** I have no browser environment in the sandbox that built this — I cannot click "Load unpacked" in real Chrome or Firefox and confirm the popup renders correctly, the icon shows up right, or `tabs.query` behaves exactly as documented. The mocks are written from documented API shapes, not verified against a live implementation. Load it yourself before trusting it:

1. `npm install && npm test` — confirms the logic itself is sound
2. Chrome: open `chrome://extensions`, enable Developer Mode, "Load unpacked", select this folder. Firefox: `about:debugging#/runtime/this-firefox`, "Load Temporary Add-on", select `manifest.json`.
3. Visit any page, click the toolbar icon, confirm the popup shows a result for the current tab
4. Try the manual-check field with a known-odd URL like `http://192.168.1.1@example.tk/login`

If any step doesn't match what `popup-test.js` predicts, the mock has a gap — that's a real bug report, not a formality.

## Files

```
extension/
├── manifest.json     Manifest V3, activeTab permission only
├── popup.html
├── popup.js           browser/chrome promise-based, cross-browser
├── engine.js          identical copy of the root engine.js
├── popup-test.js      19 checks: chrome namespace, browser namespace, rejection, no-API
├── icons/
└── package.json
```
