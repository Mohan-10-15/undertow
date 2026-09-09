const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

// This suite deliberately does NOT mock window.storage — it represents
// exactly the environment this project tells people to deploy to
// (GitHub Pages, or just opening the file), where window.storage
// genuinely does not exist and jsdom's real localStorage is the only
// thing available. If persistence doesn't work here, it doesn't work
// on the deployment target, no matter what the mocked window.storage
// tests showed.

async function run() {
  let pass = 0, fail = 0;
  function assert(label, cond) {
    console.log((cond ? 'PASS' : 'FAIL') + ' | ' + label);
    cond ? pass++ : fail++;
  }

  function makeWindow() {
    const errors = [];
    const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'https://example.com/' });
    dom.window.onerror = (msg) => errors.push(String(msg));
    // Explicitly confirm window.storage really is absent, same as a real
    // static deployment — if this ever isn't true the test below proves nothing.
    if (dom.window.storage) throw new Error('Test invalid: window.storage unexpectedly present');
    return { dom, errors };
  }

  // ---- Scan history persists via localStorage across a simulated reload ----
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#url-input').value = 'http://paypa1-secure.tk/login';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 30));

    const raw = dom.window.localStorage.getItem('undertow:undertow-scan-history');
    assert('history actually landed in real localStorage (no window.storage present)', !!raw);
    assert('stored value is valid JSON with one entry', JSON.parse(raw || '[]').length === 1);
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Reopening the app (fresh page load, pre-existing localStorage data) restores history ----
  {
    const errors = [];
    const dom = new JSDOM(html, {
      runScripts: 'dangerously',
      url: 'https://example.com/',
      beforeParse(window) {
        // Seed storage exactly as a real prior visit would have left it,
        // before this window's own init script gets a chance to run.
        window.localStorage.setItem('undertow:undertow-scan-history', JSON.stringify([
          { kind: 'url', displayTarget: 'evil.tk', score: 80, risk: 'critical', signals: [], ts: Date.now() }
        ]));
      }
    });
    dom.window.onerror = (msg) => errors.push(String(msg));
    await new Promise((r) => setTimeout(r, 30));
    const doc = dom.window.document;
    assert('reopened app restores prior scan from localStorage', doc.querySelectorAll('#history-list .history-item').length === 1);
    assert('restored entry shows the right target', doc.getElementById('history-list').textContent.includes('evil.tk'));
    assert('no runtime errors', errors.length === 0);
  }

  // ---- API key also persists via localStorage ----
  {
    const { dom, errors } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#api-key-input').value = 'my-real-key-1234';
    doc.querySelector('#save-key-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    const raw = dom.window.localStorage.getItem('undertow:undertow-safebrowsing-key');
    assert('API key landed in real localStorage', raw === 'my-real-key-1234');
    assert('no runtime errors', errors.length === 0);
  }

  // ---- Clear history removes it from localStorage too, not just memory ----
  {
    const { dom } = makeWindow();
    const doc = dom.window.document;
    await new Promise((r) => setTimeout(r, 30));
    doc.querySelector('#url-input').value = 'https://www.wikipedia.org';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    assert('something was saved before clearing', !!dom.window.localStorage.getItem('undertow:undertow-scan-history'));
    doc.querySelector('#clear-history').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    const raw = dom.window.localStorage.getItem('undertow:undertow-scan-history');
    assert('localStorage entry actually removed, not just the in-memory list', raw === null);
  }

  // ---- localStorage itself throwing (e.g. Safari private mode) degrades to in-memory, no crash ----
  {
    const errors = [];
    const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'https://example.com/' });
    dom.window.onerror = (msg) => errors.push(String(msg));
    await new Promise((r) => setTimeout(r, 20));
    // Simulate the classic Safari private-browsing behavior: localStorage
    // exists but setItem throws a QuotaExceededError.
    Object.defineProperty(dom.window, 'localStorage', {
      value: {
        getItem: () => { throw new Error('SecurityError'); },
        setItem: () => { throw new Error('QuotaExceededError'); },
        removeItem: () => { throw new Error('SecurityError'); }
      }
    });
    const doc = dom.window.document;
    doc.querySelector('#url-input').value = 'http://paypa1-secure.tk/login';
    doc.querySelector('#scan-url-btn').dispatchEvent(new dom.window.Event('click', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 20));
    assert('scan still renders a result even when localStorage throws on every call', doc.querySelector('.score-number') !== null);
    assert('no uncaught errors even though the storage backend is fully broken', errors.length === 0);
  }

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exitCode = fail > 0 ? 1 : 0;
}

run().catch((e) => { console.error('TEST CRASHED:', e); process.exitCode = 1; });
