/* global URL, console, process */
// Fails the build when the dev-only fixture layer reached the production bundle.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const MARKERS = ['cbi.example', 'czujka.fx.', 'mulberry32', 'fixture-accounts', 'dev fixtures active'];
const root = new URL('../dist', import.meta.url).pathname;

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const hits = [];
for (const file of walk(root)) {
  if (!/\.(js|css|html|map)$/.test(file)) continue;
  const text = readFileSync(file, 'utf8');
  for (const m of MARKERS) if (text.includes(m)) hits.push(file.slice(root.length + 1) + ': ' + m);
}
if (hits.length) {
  console.error('The production bundle contains the dev fixture layer:\n  ' + hits.join('\n  '));
  process.exit(1);
}
console.log('check-bundle: no fixture marker in dist');
