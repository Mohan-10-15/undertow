const fs = require('fs');
const path = require('path');
const { analyzeURL } = require('../engine.js');

const legitUrls = fs.readFileSync(path.join(__dirname, 'data/legitimate-urls.csv'), 'utf8')
  .split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

const signalCounts = {};
let flaggedCount = 0;

for (const u of legitUrls) {
  const result = analyzeURL(u);
  if (result.error || result.risk === 'low') continue;
  flaggedCount++;
  for (const s of result.signals) {
    signalCounts[s.signal.replace(/\(.*?\)/, '(...)')] = (signalCounts[s.signal.replace(/\(.*?\)/, '(...)')] || 0) + 1;
  }
}

console.log(`${flaggedCount} legitimate URLs flagged above Low. Signal frequency among them:\n`);
const sorted = Object.entries(signalCounts).sort((a, b) => b[1] - a[1]);
for (const [signal, count] of sorted) {
  console.log(`  ${String(count).padStart(6)}  (${(100 * count / flaggedCount).toFixed(1)}%)  ${signal}`);
}

console.log('\n--- Sample false positives per top signal ---');
const seen = {};
for (const u of legitUrls) {
  const result = analyzeURL(u);
  if (result.error || result.risk === 'low') continue;
  for (const s of result.signals) {
    const key = s.signal.replace(/\(.*?\)/, '(...)');
    seen[key] = seen[key] || [];
    if (seen[key].length < 3) seen[key].push(u);
  }
}
for (const [signal] of sorted.slice(0, 6)) {
  console.log(`\n${signal}:`);
  (seen[signal] || []).forEach((u) => console.log('  ' + u));
}
