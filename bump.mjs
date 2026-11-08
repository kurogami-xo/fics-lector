#!/usr/bin/env node
// Sube la versión de la app en todos los lugares. Úsalo cada vez que cambies index.html, app.js o sw.js:
//   node bump.mjs
import { readFileSync, writeFileSync } from 'node:fs';
const v = JSON.parse(readFileSync('version.json', 'utf8')).v + 1;
const sub = (f, pairs) => { let s = readFileSync(f, 'utf8'); for (const [re, to] of pairs) s = s.replace(re, to); writeFileSync(f, s); };
sub('app.js', [[/var APP_VERSION = \d+;/, `var APP_VERSION = ${v};`]]);
sub('index.html', [[/app\.js\?v=\d+/, `app.js?v=${v}`]]);
sub('sw.js', [[/fics-shell-v\d+/, `fics-shell-v${v}`], [/'app\.js\?v=\d+'/, `'app.js?v=${v}'`]]);
writeFileSync('version.json', JSON.stringify({ v }) + '\n');
console.log('Versión de la app:', v);
