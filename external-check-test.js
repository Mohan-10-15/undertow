const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

async function run() {
  let pass = 0, fail = 0;
  function assert(label, cond) {
    console.log((cond ? 'PASS' : 'FAIL') + ' | ' + label);
    cond ? pass++ : fail++;
  }

  let fetchMode = 'clean'; // 'clean' | 'flagged' | 'reject' | 'http-error' | 'abort'
  const fetchCalls = [];

  function makeWindow() {
    const errors = [];
    const dom = new JSDOM(html, {
      runScripts: 'dangerously',
      url: 'https://example.com/',
      beforeParse(window) {
        window.storage = (function () {
          const store = {};
          return {
            get: async (k) => (k in store ? { key: k, value: store[k] } : null),
            set: async (k, v) => { store[k] = v; },
            delete: async (k) => { delete store[k]; }
          };
        })();

        window.fetch = function (url, options) {
          fetchCalls.push({ url, options });
          if (fetchMode === 'reject') {
            return Promise.reject(new TypeError('Failed to fetch'));
          }
          if (fetchMode === 'abort') {
            const err = new Error('The operation was aborted');
            err.name = 'AbortError';
            return Promise.reject(err);
          }
          if (fetchMode === 'http-error') {
            return Promise.resolve({
              ok: false,
              status: 400,
              text: () => Promise.resolve('API key not valid')
            });
          }
          const body = fetchMode === 'flagged'
            ? { matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }
            : {};
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
        };
      }
    });
    dom.window.onerror = (msg) => errors.push(String(msg));
    return { dom, errors };
  }

  // ---- No key configured: external-check slot should not appear ----
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#url-input').value = 'http://paypa1-secure.tk/login';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    const slot = doc.querySelector('.external-check');
    assert('no key: external-check slot stays hidden', !slot || slot.hidden === true);
    assert('no key: no fetch was attempted', fetchCalls.length === 0);
    assert('no key: no runtime errors', errors.length === 0);
  }

  // ---- Save a key, then scan: clean result ----
  fetchCalls.length = 0;
  fetchMode = 'clean';
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));

    doc.querySelector('#api-key-input').value = 'test-key-ABCD1234';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    assert('save key: status text updates', doc.querySelector('#key-status').textContent.includes('ends in 1234'));

    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));

    assert('clean: fetch was called once', fetchCalls.length === 1);
    assert('clean: fetch targeted the Safe Browsing endpoint', fetchCalls[0].url.includes('safebrowsing.googleapis.com'));
    assert('clean: request body includes the scanned URL', JSON.parse(fetchCalls[0].options.body).threatInfo.threatEntries[0].url === 'https://www.wikipedia.org/');
    const slot = doc.querySelector('.external-check');
    assert('clean: slot shows the clean message', slot.textContent.includes('Not found on Google Safe Browsing'));
    assert('clean: slot has is-clean class', slot.classList.contains('is-clean'));
    assert('clean: no runtime errors', errors.length === 0);
  }

  // ---- Flagged result ----
  fetchCalls.length = 0;
  fetchMode = 'flagged';
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'test-key-WXYZ9999';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    doc.querySelector('#url-input').value = 'http://totally-legit-site.com';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));
    const slot = doc.querySelector('.external-check');
    assert('flagged: slot reports the threat type', slot.textContent.includes('SOCIAL_ENGINEERING'));
    assert('flagged: slot has is-flagged class', slot.classList.contains('is-flagged'));
    assert('flagged: no runtime errors', errors.length === 0);
  }

  // ---- Network failure (simulating CORS block) — must degrade gracefully ----
  fetchCalls.length = 0;
  fetchMode = 'reject';
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'test-key-FAIL0000';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));
    const slot = doc.querySelector('.external-check');
    assert('network failure: heuristic result still rendered', doc.querySelector('.score-number') !== null);
    assert('network failure: slot shows unavailable message, not a crash', slot.textContent.includes('External check unavailable'));
    assert('network failure: slot has is-error class', slot.classList.contains('is-error'));
    assert('network failure: app did not throw', errors.length === 0);
  }

  // ---- Abort/timeout path ----
  fetchCalls.length = 0;
  fetchMode = 'abort';
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'test-key-SLOW0000';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));
    const slot = doc.querySelector('.external-check');
    assert('timeout: slot reports timed out', slot.textContent.includes('timed out'));
    assert('timeout: no runtime errors', errors.length === 0);
  }

  // ---- HTTP error (e.g. invalid key) ----
  fetchCalls.length = 0;
  fetchMode = 'http-error';
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'bad-key';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));
    const slot = doc.querySelector('.external-check');
    assert('http error: slot shows the status in the message', slot.textContent.includes('400') || slot.textContent.includes('unavailable'));
    assert('http error: no runtime errors', errors.length === 0);
  }

  // ---- Clear key removes it from storage and future scans skip the check ----
  fetchCalls.length = 0;
  fetchMode = 'clean';
  {
    const { dom } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'temp-key';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    doc.querySelector('#clear-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    assert('clear key: status reverts to no-key message', doc.querySelector('#key-status').textContent.includes('No key saved'));
    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    assert('clear key: no fetch happens after clearing', fetchCalls.length === 0);
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exitCode = fail > 0 ? 1 : 0;
}

run().catch((e) => { console.error('TEST CRASHED:', e); process.exitCode = 1; });
