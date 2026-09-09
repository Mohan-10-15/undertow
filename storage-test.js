const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const errors = [];

async function run() {
  const mockBackend = {}; // simulates the persistent key-value store

  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'https://example.com/',
    beforeParse(window) {
      window.storage = {
        get: async (key, shared) => {
          if (!(key in mockBackend)) return null;
          return { key, value: mockBackend[key], shared: !!shared };
        },
        set: async (key, value, shared) => {
          mockBackend[key] = value;
          return { key, value, shared: !!shared };
        },
        delete: async (key, shared) => {
          const existed = key in mockBackend;
          delete mockBackend[key];
          return { key, deleted: existed, shared: !!shared };
        },
        list: async () => ({ keys: Object.keys(mockBackend) })
      };
    }
  });
  const { window } = dom;
  window.onerror = (msg) => errors.push(String(msg));

  await new Promise((r) => setTimeout(r, 50));
  const doc = window.document;
  const $ = (sel) => doc.querySelector(sel);
  function assert(label, cond) {
    console.log((cond ? 'PASS' : 'FAIL') + ' | ' + label);
    if (!cond) process.exitCode = 1;
  }

  // Scan something so there's history to persist
  $('#url-input').value = 'http://192.168.0.5@evil.tk/login';
  $('#scan-url-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 30)); // allow the async saveHistory() to complete

  assert('mock backend received a write', 'undertow-scan-history' in mockBackend);
  const stored = JSON.parse(mockBackend['undertow-scan-history']);
  assert('stored history has one entry', stored.length === 1);
  assert('stored entry has expected shape', stored[0].risk && typeof stored[0].score === 'number');

  // Simulate reopening the app: fresh DOM, same backend, should load prior history
  const dom2 = new JSDOM(html, {
    runScripts: 'dangerously',
    url: 'https://example.com/',
    beforeParse(window) {
      window.storage = {
        get: async (key) => (key in mockBackend ? { key, value: mockBackend[key] } : null),
        set: async (key, value) => { mockBackend[key] = value; },
        delete: async (key) => { delete mockBackend[key]; }
      };
    }
  });
  await new Promise((r) => setTimeout(r, 50));
  const doc2 = dom2.window.document;
  assert('reopened app restores prior scan from storage',
    doc2.querySelectorAll('#history-list .history-item').length === 1);

  assert('no uncaught errors with storage present', errors.length === 0);
  if (errors.length) console.log('ERRORS:', errors);
  console.log('\nDone.');
}

run().catch((e) => { console.error('TEST CRASHED:', e); process.exitCode = 1; });
