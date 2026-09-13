const { analyzeURL, analyzeEmail } = require('./engine.js');

let pass = 0, fail = 0;
function check(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? 'PASS' : 'FAIL'} | ${label} -> got ${actual}, expected ${expected}`);
  ok ? pass++ : fail++;
}

console.log('--- Legitimate URLs (expect low) ---');
check('google.com', analyzeURL('https://www.google.com').risk, 'low');
check('github.com repo path', analyzeURL('https://github.com/anthropics/claude').risk, 'low');
check('amazon product page', analyzeURL('https://www.amazon.com/dp/B08N5WRWNW').risk, 'low');
check('bank plain domain', analyzeURL('https://www.chase.com/personal/login').risk, 'low');
check('gov site', analyzeURL('https://www.irs.gov/refunds').risk, 'low');

console.log('\n--- Official sites with brand in a subdomain (regression: were high/medium) ---');
check('mail.google.com', analyzeURL('https://mail.google.com').risk, 'low');
check('accounts.google.com login', analyzeURL('https://accounts.google.com/signin/v2/identifier').risk, 'low');
check('support.apple.com', analyzeURL('https://support.apple.com').risk, 'low');
check('account.microsoft.com', analyzeURL('https://account.microsoft.com').risk, 'low');
check('login.microsoftonline.com', analyzeURL('https://login.microsoftonline.com').risk, 'low');
check('login.live.com', analyzeURL('https://login.live.com').risk, 'low');
check('securelogin.arubanetworks.com', analyzeURL('https://securelogin.arubanetworks.com').risk, 'low');
check('archive.org deep path', analyzeURL('https://web.archive.org/web/20240101000000/https://example.com/very/deep/path/here').risk, 'low');

console.log('\n--- Short/brand-near-miss coincidence (regression: were high) ---');
check('abc.go.com (was near-miss "sbi")', analyzeURL('https://abc.go.com/shows').risk, 'low');
check('doodle.com (was near-miss "google")', analyzeURL('https://www.doodle.com').risk, 'low');
check('bmi.ir (was near-miss "sbi")', analyzeURL('http://bmi.ir').risk, 'low');
check('ap.org (expanded list: was near-miss "att")', analyzeURL('https://ap.org').risk, 'low');

console.log('\n--- Phishing-style URLs (expect medium/high/critical) ---');
console.log(JSON.stringify(analyzeURL('http://192.168.1.50/secure/login'), null, 2));
check('raw IP + login', analyzeURL('http://192.168.1.50/secure/login').risk !== 'low', true);
check('typosquat paypa1', analyzeURL('http://paypa1-secure.com/login').risk !== 'low', true);
check('brand in subdomain trick', analyzeURL('http://paypal.com.verify-account.xyz/login').risk !== 'low', true);
check('at-symbol trick', analyzeURL('http://google.com@evil-site.tk/phish').risk !== 'low', true);
check('shortener', analyzeURL('http://bit.ly/3xample').risk !== 'low', true);
check('many hyphens + suspicious tld', analyzeURL('http://secure-login-verify-account.top').risk !== 'low', true);
check('amaz0n leetspeak', analyzeURL('http://amaz0n-support.com/order').risk !== 'low', true);
check('hyphen-split brand in subdomain (ama-zon)', analyzeURL('http://ama-zon.huananshangcheng.com/order').risk !== 'low', true);
check('brand in subdomain of unrelated domain (whatsappnew)', analyzeURL('http://whatsappnew.ooguy.com/').risk !== 'low', true);

console.log('\n--- Edge cases (must not crash) ---');
console.log('empty:', JSON.stringify(analyzeURL('')));
console.log('garbage:', JSON.stringify(analyzeURL('not a url at all!!')));
console.log('just word:', JSON.stringify(analyzeURL('hello')));
console.log('whitespace:', JSON.stringify(analyzeURL('   ')));
console.log('no-protocol legit:', JSON.stringify(analyzeURL('amazon.com')));
check('empty gives error not crash', !!analyzeURL('').error, true);
check('garbage gives error not crash', !!analyzeURL('not a url at all!!').error, true);
check('bare domain works without protocol', analyzeURL('amazon.com').risk, 'low');

console.log('\n--- Email analysis ---');
const legitEmail = "Hi Priya, thanks for the update on the quarterly report. Let's sync tomorrow at 10am. Best, Raj";
console.log('legit email:', JSON.stringify(analyzeEmail(legitEmail)));
check('legit email is low', analyzeEmail(legitEmail).risk, 'low');

const phishEmail = "Dear Customer, we detected unusual activity on your account. Verify within 24 hours or your account will be suspended. Please confirm your password and card number immediately at the link below.";
console.log('phishing email:', JSON.stringify(analyzeEmail(phishEmail), null, 2));
check('phishing email is high/critical', ['high', 'critical'].includes(analyzeEmail(phishEmail).risk), true);

check('empty email gives error', !!analyzeEmail('').error, true);
check('empty email gives error (whitespace)', !!analyzeEmail('   ').error, true);

console.log(`\n=== ${pass} passed, ${fail} failed ===`);
process.exit(fail > 0 ? 1 : 0);
