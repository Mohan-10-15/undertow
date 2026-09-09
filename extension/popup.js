(function () {
  'use strict';

  var RISK_META = {
    low:      { label: 'Low risk',      color: getComputedStyle(document.documentElement).getPropertyValue('--safe').trim() },
    medium:   { label: 'Medium risk',   color: getComputedStyle(document.documentElement).getPropertyValue('--caution').trim() },
    high:     { label: 'High risk',     color: getComputedStyle(document.documentElement).getPropertyValue('--high').trim() },
    critical: { label: 'Critical risk', color: getComputedStyle(document.documentElement).getPropertyValue('--critical').trim() }
  };

  var currentUrlEl = document.getElementById('current-url');
  var loadingEl = document.getElementById('loading');
  var cardEl = document.getElementById('result-card');
  var manualInput = document.getElementById('manual-url');
  var manualBtn = document.getElementById('manual-scan-btn');

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'style') node.style.cssText = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    (children || []).forEach(function (c) {
      if (c == null) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function renderResult(result) {
    loadingEl.hidden = true;
    cardEl.hidden = false;
    cardEl.innerHTML = '';

    if (result.error) {
      cardEl.appendChild(el('p', { class: 'result-error' }, [result.error]));
      return;
    }

    var meta = RISK_META[result.risk];
    var head = el('div', { class: 'result-head' }, [
      el('span', { class: 'score-number' }, [String(result.score)]),
      el('span', { class: 'risk-label', style: 'background:' + meta.color + '22; color:' + meta.color }, [meta.label])
    ]);
    cardEl.appendChild(head);

    var track = el('div', { class: 'gauge-track' }, [
      el('div', { class: 'gauge-marker', style: 'left:' + Math.max(1.5, Math.min(98.5, result.score)) + '%; background:' + meta.color })
    ]);
    cardEl.appendChild(track);

    if (result.signals.length === 0) {
      cardEl.appendChild(el('div', { class: 'clean-message' }, [
        el('strong', {}, ['No red flags found.']),
        document.createTextNode('Not a certainty — still check the address bar before entering anything sensitive.')
      ]));
    } else {
      var list = el('ul', { class: 'signal-list' });
      result.signals
        .slice()
        .sort(function (a, b) { return b.weight - a.weight; })
        .forEach(function (s) {
          list.appendChild(el('li', { class: 'signal-item', style: 'border-left-color:' + meta.color }, [
            el('div', { class: 'signal-name' }, [s.signal]),
            el('div', { class: 'signal-detail' }, [s.detail])
          ]));
        });
      cardEl.appendChild(list);
    }
  }

  function checkUrl(url) {
    loadingEl.hidden = false;
    cardEl.hidden = true;
    var result = analyzeURL(url);
    renderResult(result);
  }

  manualBtn.addEventListener('click', function () {
    if (manualInput.value.trim()) checkUrl(manualInput.value);
  });
  manualInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && manualInput.value.trim()) checkUrl(manualInput.value);
  });

  // Firefox/Safari expose `browser` (promise-based, standards-track);
  // Chrome/Edge expose `chrome`. Chrome's MV3 chrome.tabs.query also
  // returns a promise when called with no callback, so one promise-based
  // call path covers all three without leaning on Firefox's chrome.*
  // callback shim, which MDN documents as "not part of the WebExtensions
  // standard and may not be supported by all compliant browsers."
  var extAPI = typeof browser !== 'undefined' ? browser : (typeof chrome !== 'undefined' ? chrome : null);

  if (extAPI && extAPI.tabs && extAPI.tabs.query) {
    Promise.resolve(extAPI.tabs.query({ active: true, currentWindow: true }))
      .then(function (tabs) {
        var tab = tabs && tabs[0];
        var url = tab && tab.url;
        if (!url) {
          currentUrlEl.textContent = 'Could not read the current tab.';
          loadingEl.hidden = true;
          return;
        }
        currentUrlEl.textContent = url;
        if (!/^https?:\/\//i.test(url)) {
          loadingEl.hidden = true;
          cardEl.hidden = false;
          cardEl.appendChild(el('p', { class: 'result-error' }, ["This isn't a web page Undertow can check — try the manual check below."]));
          return;
        }
        checkUrl(url);
      })
      .catch(function () {
        currentUrlEl.textContent = 'Could not read the current tab.';
        loadingEl.hidden = true;
      });
  } else {
    currentUrlEl.textContent = 'Not running as an installed extension — use the manual check below.';
    loadingEl.hidden = true;
  }
})();
