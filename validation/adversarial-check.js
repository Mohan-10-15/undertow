// This is not a bug hunt — it's a threat-model check. Precision/recall
// against a historical dataset says nothing about resistance to an
// attacker who has actually read engine.js, which anyone can, since it's
// open source. These URLs are constructed the way that attacker would:
// pick a domain not in POPULAR_BRANDS, use HTTPS, stay under every
// numeric threshold, avoid every listed keyword combination. None of
// these are real phishing URLs — they're realistic *shapes* a real one
// would take once its author has read this file.

const { analyzeURL } = require('../engine.js');

const adversarial = [
  // Plausible-sounding brand-adjacent domain, not in the ~30-brand list
  'https://myaccount-secure-portal.com/session',
  // Single suspicious keyword only (the fallback check needs >= 2)
  'https://billing-update.com/invoice',
  // Generic urgency-adjacent wording with no listed keyword at all
  'https://quick-confirm.net/here',
  // Brand-adjacent but not a real brand, clean TLD, HTTPS, short
  'https://secure-hdfc-online.net/login',
  // Convincing bank-sounding name, invented, not a near-miss of a real one
  'https://unitedtrust-bank.com/verify-identity',
  // Newly-registered-style domain with no structural red flags at all
  'https://cloudsync-storage.io/shared/doc',
  // Two hyphens (under the 3-hyphen threshold), one keyword only
  'https://my-account-center.com/dashboard',
];

console.log('Adversarial check: URLs shaped to evade every current heuristic\n');
let allLow = 0;
adversarial.forEach((u) => {
  const r = analyzeURL(u);
  const status = r.risk === 'low' ? 'EVADES — scored Low, no meaningful flag' : `caught (${r.risk}, score ${r.score})`;
  if (r.risk === 'low') allLow++;
  console.log(`${status.padEnd(45)} ${u}`);
  if (r.signals && r.signals.length) {
    r.signals.forEach((s) => console.log(`    - ${s.signal} (+${s.weight})`));
  }
});

console.log(`\n${allLow}/${adversarial.length} constructed examples scored Low risk — indistinguishable from a legitimate site to this tool.`);
console.log('\nThis is not fixable by adding more rules to this list: every rule added');
console.log('here is equally visible to an attacker reading the same file, who can');
console.log('route around it by construction. That\'s the structural limit of any');
console.log('published, heuristic, client-side detector — not a bug to patch, a');
console.log('property of the approach. The real mitigation is the optional Safe');
console.log('Browsing layer (a threat-intel source an attacker can\'t read the rules');
console.log('of in advance) — run these same URLs through that check for comparison');
console.log('if you have a key configured.');
