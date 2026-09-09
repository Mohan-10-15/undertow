const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const popupHtml = fs.readFileSync(path.join(__dirname, 'popup.html'), 'utf8');
const engineSrc = fs.readFileSync(path.join(__dirname, 'engine.js'), 'utf8');
const popupSrc = fs.readFileSync(path.join(__dirname, 'popup.js'), 'utf8');

// jsdom's runScripts executes <script src="..."> only if it can actually
// fetch that path; rather than standing up a file server, inline the two
// script bodies in place of the src tags — same code, same execution
// order, no network needed.
const inlinedHtml = popupHtml
  .replace('<script src="engine.js"></script>', '<script>' + engineSrc + '</script>')
  .replace('<script src="popup.js"></script>', '<script>' + popupSrc + '</script>');

async function run() {
  let pass = 0, fail = 0;
  function assert(label, cond) {
    console.log((cond ? 'PASS' : 'FAIL') + ' | ' + label);
    cond ? pass++ : fail++;
  }

  function makeDom(mockTabUrl, namespace) {
    namespace = namespace || 'chrome';
    const errors = [];
    const dom = new JSDOM(inlinedHtml, {
      runScripts: 'dangerously',
      url: 'https://example.com/',
      beforeParse(window) {
        window[namespace] = {
          tabs: {
            query: function () {
              return Promise.resolve(mockTabUrl === undefined ? [] : [{ url: mockTabUrl }]);
            }
          }
        };
      }
    });
    dom.window.onerror = (msg) => errors.push(String(msg));
    return { dom, errors };
  }

  // ---- Suspicious current tab gets auto-checked and flagged ----
  {
    const { dom, errors } = makeDom('http://paypa1-secure-login.tk/verify');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('current URL displayed', doc.getElementById('current-url').textContent.includes('paypa1'));
    assert('result card shown', doc.getElementById('result-card').hidden === false);
    assert('loading indicator hidden after result', doc.getElementById('loading').hidden === true);
    assert('flagged something (score > 0)', parseInt(doc.querySelector('.score-number').textContent, 10) > 0);
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Clean current tab ----
  {
    const { dom, errors } = makeDom('https://www.wikipedia.org/');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('clean tab shows the reassuring message', doc.getElementById('result-card').textContent.includes('No red flags'));
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Newly-added brand (zoom) impersonation ----
  {
    const { dom, errors } = makeDom('http://zoom-secure-login.com/meeting');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('new brand (zoom) impersonation flagged', parseInt(doc.querySelector('.score-number').textContent, 10) > 0);
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Non-http tab (e.g. a chrome:// settings page) ----
  {
    const { dom, errors } = makeDom('chrome://extensions/');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('non-http tab shows a friendly message, not a crash', doc.getElementById('result-card').textContent.includes("isn't a web page"));
    assert('no runtime errors', errors.length === 0);
  }

  // ---- No active tab returned ----
  {
    const { dom, errors } = makeDom(undefined);
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('missing tab handled gracefully', doc.getElementById('current-url').textContent.includes('Could not read'));
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Manual check still works independent of the active tab ----
  {
    const { dom, errors } = makeDom('https://www.wikipedia.org/');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    doc.getElementById('manual-url').value = 'http://192.168.1.1@fake-bank.tk/login';
    doc.getElementById('manual-scan-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    assert('manual check overrides the displayed result', parseInt(doc.querySelector('.score-number').textContent, 10) > 0);
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Firefox/Safari's `browser` namespace (promise-based), not `chrome` ----
  {
    const { dom, errors } = makeDom('http://paypa1-secure-login.tk/verify', 'browser');
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('browser namespace: current URL displayed', doc.getElementById('current-url').textContent.includes('paypa1'));
    assert('browser namespace: result rendered', doc.getElementById('result-card').hidden === false);
    assert('browser namespace: no runtime errors', errors.length === 0);
  }

  // ---- Both namespaces absent (query rejects) — must degrade, not crash ----
  {
    const errors = [];
    const dom = new JSDOM(inlinedHtml, {
      runScripts: 'dangerously',
      url: 'https://example.com/',
      beforeParse(window) {
        window.chrome = { tabs: { query: function () { return Promise.reject(new Error('permission denied')); } } };
      }
    });
    dom.window.onerror = (msg) => errors.push(String(msg));
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('rejected query degrades to a clear message, not a crash', doc.getElementById('current-url').textContent.includes('Could not read'));
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Running outside an extension context (e.g. opened as a plain file) ----
  {
    const dom = new JSDOM(inlinedHtml, { runScripts: 'dangerously', url: 'https://example.com/' });
    // neither window.chrome nor window.browser defined at all
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('degrades to a clear message with no extension API present', doc.getElementById('current-url').textContent.includes('Not running as an installed extension'));
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exitCode = fail > 0 ? 1 : 0;
}

run().catch((e) => { console.error('TEST CRASHED:', e); process.exitCode = 1; });
