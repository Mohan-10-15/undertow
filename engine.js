// PhishGuard detection engine — standalone module for testing.
// This exact logic gets embedded into the final HTML app once verified.

const POPULAR_BRANDS = [
  'google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft',
  'netflix', 'instagram', 'twitter', 'linkedin', 'bankofamerica',
  'wellsfargo', 'chase', 'citibank', 'ebay', 'dropbox', 'adobe',
  'yahoo', 'outlook', 'gmail', 'whatsapp', 'spotify', 'github',
  'icloud', 'hdfcbank', 'icicibank', 'sbi', 'paytm', 'flipkart',
  'samsung', 'alibaba', 'tencent', 'wechat', 'tiktok',
  'discord', 'coinbase', 'binance', 'revolut', 'hsbc', 'barclays',
  'santander', 'rakuten', 'mercadolibre', 'americanexpress',
  'mastercard', 'docusign', 'salesforce', 'airbnb', 'venmo',
  'westernunion'
];
// This list is inherently incomplete — there is no bounded set of "all
// brands," and every entry here is equally visible to anyone reading
// this file (see validation/adversarial-check.js). Additions are
// validated against validation/data before merging, not just assumed
// safe: "telegram" was tried and dropped after validation showed it
// collides with telegraf.com.ua (a real Ukrainian news site — "telegraf"
// is just the word "telegraph," one edit away from "telegram," not a
// phishing attempt) — a concrete demonstration that a short or common-
// word-adjacent brand string can reintroduce the exact false-positive
// class fixed earlier (see README, the "t.co" substring bug).

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.support', '.click',
  '.loan', '.men', '.win', '.bid', '.review', '.download', '.gq', '.tk', '.ml', '.cf', '.ga'];

const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
  'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'rebrand.ly'];

const SUSPICIOUS_KEYWORDS = ['secure', 'verify', 'account', 'update', 'confirm',
  'login', 'signin', 'banking', 'suspend', 'urgent', 'validate', 'unlock'];

function levenshtein(a, b) {
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = b.charAt(i - 1) === a.charAt(j - 1)
        ? m[i - 1][j - 1]
        : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1);
    }
  }
  return m[b.length][a.length];
}

function normalizeLeet(str) {
  const map = { '0': 'o', '1': 'l', '3': 'e', '5': 's', '4': 'a', '7': 't', '@': 'a' };
  return str.split('').map(c => map[c] || c).join('');
}

function analyzeURL(rawUrlInput) {
  const rawUrl = (rawUrlInput || '').trim();
  if (!rawUrl) return { error: 'Enter a URL to analyze.' };

  let url;
  try {
    let testUrl = rawUrl;
    if (!/^https?:\/\//i.test(testUrl)) testUrl = 'http://' + testUrl;
    url = new URL(testUrl);
  } catch (e) {
    return { error: "That doesn't look like a valid URL." };
  }

  if (!url.hostname.includes('.')) {
    return { error: "That doesn't look like a valid URL." };
  }

  const hostname = url.hostname.toLowerCase();
  const signals = [];
  let score = 0;

  const add = (signal, weight, detail) => { signals.push({ signal, weight, detail }); score += weight; };

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    add('IP address used as the domain', 30, 'Legitimate sites are almost never linked as raw IP addresses.');
  }
  if (url.protocol !== 'https:') {
    add('No HTTPS encryption', 10, 'The connection to this site would not be encrypted.');
  }
  if (url.username || url.password) {
    add('"@" symbol hides the real destination', 25, 'Everything before an "@" in the address bar is ignored by browsers — a classic way to disguise where a link actually goes.');
  }
  const subdomainCount = Math.max(0, hostname.split('.').length - 2);
  if (subdomainCount >= 3) {
    add(`Excessive subdomains (${subdomainCount})`, 20, 'Stacking subdomains is a common trick to make a fake URL look like a trusted one.');
  } else if (subdomainCount === 2) {
    add('Multiple subdomains', 8, 'Worth a second look — not disqualifying on its own.');
  }
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    add(`Many hyphens in the domain (${hyphenCount})`, 15, 'Real brand domains rarely need this many hyphens.');
  }
  if (rawUrl.length > 200) {
    add('Unusually long URL', 10, 'Excessive length can be used to bury the real destination. (Threshold set from real-world legitimate URL length data — see validation/.)');
  }
  const tld = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t));
  if (tld) {
    add(`High-risk domain ending (${tld})`, 15, 'This ending is cheap to register and frequently used for throwaway phishing sites.');
  }
  if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
    add('URL shortener', 15, 'Hides the real destination until after you click.');
  }
  if (hostname.includes('xn--')) {
    add('Encoded (punycode) domain', 25, 'Can render as look-alike letters from another alphabet — used for homograph attacks.');
  }

  const mainDomain = hostname.replace(/^www\./, '').split('.')[0];
  const normalizedHostname = normalizeLeet(hostname);
  let brandFlagged = false;
  const isKnownBrandExactly = POPULAR_BRANDS.indexOf(mainDomain) !== -1;
  if (!isKnownBrandExactly) {
    for (const brand of POPULAR_BRANDS) {
      if (hostname.includes(brand) && mainDomain !== brand) {
        add(`Contains "${brand}" but isn't their domain`, 30, 'A common way to impersonate a trusted brand.');
        brandFlagged = true;
        break;
      }
      // Leetspeak substitution anywhere in the hostname, e.g. "paypa1-secure.com"
      if (normalizedHostname.includes(brand) && !hostname.includes(brand)) {
        add(`Impersonates "${brand}" using look-alike characters`, 35, `Swapping numbers for letters (like 0/1/3/5) makes this mimic "${brand}".`);
        brandFlagged = true;
        break;
      }
      // Near-misspelling of the whole domain, e.g. "gooogle.com"
      const distance = levenshtein(normalizeLeet(mainDomain), brand);
      if (distance > 0 && distance <= 2 && Math.abs(mainDomain.length - brand.length) <= 2) {
        add(`Impersonates "${brand}"`, 35, `Domain is a near-misspelling of "${brand}".`);
        brandFlagged = true;
        break;
      }
    }
  }
  if (!brandFlagged) {
    const hits = SUSPICIOUS_KEYWORDS.filter(k => hostname.includes(k));
    if (hits.length >= 2) {
      add(`Multiple suspicious keywords (${hits.join(', ')})`, 15, 'Common wording on credential-harvesting pages.');
    }
  }

  score = Math.min(score, 100);
  const risk = score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : 'low';
  return { score, signals, risk, hostname, normalizedUrl: url.href };
}

const URGENCY_PHRASES = ['act now', 'immediate action', 'act immediately', 'account will be suspended',
  'account will be closed', 'verify within', '24 hours', 'limited time', 'act today', 'final notice',
  'unusual activity', 'unauthorized access'];
const SENSITIVE_REQUESTS = ['password', 'social security', 'ssn', 'credit card number', 'card number',
  'cvv', 'pin number', 'one-time password', 'otp', 'verification code', 'bank account number', 'login credentials'];
const GENERIC_GREETINGS = ['dear customer', 'dear user', 'dear member', 'dear valued customer',
  'dear account holder', 'attention customer'];

function analyzeEmail(textInput) {
  const text = textInput || '';
  if (!text.trim()) return { error: 'Paste an email to analyze.' };
  const lower = text.toLowerCase();
  const signals = [];
  let score = 0;
  const add = (signal, weight, detail) => { signals.push({ signal, weight, detail }); score += weight; };

  const urgencyHits = URGENCY_PHRASES.filter(p => lower.includes(p));
  if (urgencyHits.length > 0) {
    add('Urgency or pressure language', 18 * Math.min(urgencyHits.length, 2),
      `Phrases like "${urgencyHits[0]}" push you to act before thinking it through.`);
  }
  const sensitiveHits = SENSITIVE_REQUESTS.filter(p => lower.includes(p));
  if (sensitiveHits.length > 0) {
    add('Asks for sensitive information', 35, `Mentions "${sensitiveHits[0]}" — legitimate organizations rarely request this by email.`);
  }
  const greetingHit = GENERIC_GREETINGS.find(g => lower.includes(g));
  if (greetingHit) {
    add('Generic greeting', 15, 'Addresses you generically instead of by name — typical of mass phishing campaigns.');
  }
  const urlMatches = text.match(/https?:\/\/[^\s<>"']+/g) || [];
  if (urlMatches.length > 0) {
    add(`Contains ${urlMatches.length} link${urlMatches.length > 1 ? 's' : ''}`, 5, 'Paste each link into the URL Scanner tab to check it individually.');
  }
  if (/\.(exe|scr|bat|js|jar)\b/i.test(text)) {
    add('Mentions a risky attachment type', 20, 'Executable attachments are a common malware delivery method.');
  }

  score = Math.min(score, 100);
  const risk = score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : 'low';
  return { score, signals, risk };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeURL, analyzeEmail };
}
