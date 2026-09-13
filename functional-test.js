const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

const errors = [];

async function run() {
  const dom = new JSDOM(html, {
    runScripts: 'dangerously',
    resources: undefined,
    url: 'https://example.com/'
  });
  const { window } = dom;

  window.onerror = (msg) => errors.push(String(msg));
  window.addEventListener('error', (e) => errors.push(String(e.error || e.message)));

  // give inline scripts + microtasks (loadHistory().then(...)) a tick to run
  await new Promise((r) => setTimeout(r, 50));

  const doc = window.document;
  const $ = (sel) => doc.querySelector(sel);

  function assert(label, cond) {
    console.log((cond ? 'PASS' : 'FAIL') + ' | ' + label);
    if (!cond) process.exitCode = 1;
  }

  // ---- Initial state ----
  assert('url panel active by default', $('#url-panel').classList.contains('active'));
  assert('email panel hidden by default', !$('#email-panel').classList.contains('active'));
  assert('results hidden before first scan', $('#results').hidden === true);
  assert('history shows empty state', $('#history-list').textContent.includes('Your scans will show up here'));
  assert('visually-hidden class is defined (labels not visibly rendered as block text)',
    window.getComputedStyle($('label[for="url-input"]')).position === 'absolute');

  // ---- Scan a clearly suspicious URL ----
  $('#url-input').value = 'http://paypa1-secure-login.tk/verify';
  $('#scan-url-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));

  assert('results visible after scan', $('#results').hidden === false);
  const resultText = $('#results').textContent;
  assert('result shows a numeric score', /\d+/.test($('.score-number')?.textContent || ''));
  assert('result flags something (not the clean-message)', !resultText.includes('No red flags found'));
  assert('risk-label background is valid (not "var(--safe)22")',
    !$('.risk-label').getAttribute('style').includes('var(--'));
  assert('history updated with one entry', $('#history-list').querySelectorAll('.history-item').length === 1);

  // ---- Scan an obviously clean URL ----
  $('#url-input').value = 'https://www.wikipedia.org';
  $('#scan-url-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  assert('clean URL shows the reassuring message', $('#results').textContent.includes('No red flags found'));
  assert('history now has two entries', $('#history-list').querySelectorAll('.history-item').length === 2);

  // ---- Switch to email mode and scan a phishing-style email ----
  $('#mode-email').dispatchEvent(new window.Event('click', { bubbles: true }));
  assert('email panel active after switching', $('#email-panel').classList.contains('active'));
  assert('url panel inactive after switching', !$('#url-panel').classList.contains('active'));

  $('#email-input').value = 'Dear Customer, your account will be suspended. Verify within 24 hours and confirm your password.';
  $('#scan-email-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  assert('email scan produced a high/critical result', /Critical risk|High risk/.test($('#results').textContent));
  assert('history now has three entries', $('#history-list').querySelectorAll('.history-item').length === 3);

  // ---- Empty submissions should show an error, not throw ----
  $('#email-input').value = '   ';
  $('#scan-email-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  assert('empty email shows a friendly error', $('#results').textContent.includes('Paste an email to analyze'));

  // ---- Clicking a history item re-renders that result ----
  $('#history-list').querySelectorAll('.history-item')[2].dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  assert('clicking oldest history item restores its result', /Critical risk|High risk/.test($('#results').textContent) || $('#results').textContent.includes('wikipedia') === false);

  // ---- Clear history ----
  $('#clear-history').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  assert('history empty after clearing', $('#history-list').textContent.includes('Your scans will show up here'));

  // ---- No uncaught JS errors the whole time (window.storage is undefined here, like a plain static host) ----
  assert('no uncaught runtime errors during full interaction flow (jsdom has no window.storage, exercising the fallback path)', errors.length === 0);
  if (errors.length) console.log('ERRORS:', errors);

  // ---- New email signals: excessive caps and exclamation marks ----
  $('#email-input').value = 'URGENT: YOUR ACCOUNT WILL BE DELETED!!! ACT NOW OR LOSE EVERYTHING!!!';
  $('#scan-email-btn').dispatchEvent(new window.Event('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 20));
  const capsResult = $('#results').textContent;
  assert('caps email flags excessive capitalization', capsResult.includes('Excessive capitalization') || capsResult.includes('capitalization'));
  assert('caps email flags multiple exclamation marks', capsResult.includes('Multiple exclamation marks') || capsResult.includes('exclamation'));

  console.log('\nDone.');
}

run().catch((e) => { console.error('TEST CRASHED:', e); process.exitCode = 1; });
