import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const html = fs.readFileSync('docs/index.html', 'utf8');
const blitz = fs.readFileSync('docs/blitz.css', 'utf8');
const start = blitz.indexOf('/*\n * iPhone viewport guardrails');
const mobile = blitz.slice(start);

test('iPhone breakpoints keep Lock visible and shrink nested grids without horizontal page clipping', () => {
  assert.match(html, /name="viewport" content="width=device-width, initial-scale=1"/);
  assert.ok(start >= 0, 'Small-screen guardrails are present');
  assert.match(mobile, /@media\s*\(max-width:600px\)/);
  assert.match(mobile, /\.topbar\{display:grid;grid-template-columns:minmax\(0,1fr\) auto/);
  assert.match(mobile, /\.brand\{gap:7px;min-width:0;overflow:hidden/);
  assert.match(mobile, /\.brand-sub\{[^}]*overflow:hidden;white-space:nowrap;text-overflow:ellipsis/);
  assert.match(mobile, /\.top-actions \.btn\{min-height:44px/);
  assert.match(mobile, /\.content\{grid-template-columns:minmax\(0,1fr\);max-width:100%;min-width:0/);
  assert.match(mobile, /\.hero\{grid-template-columns:minmax\(0,1fr\)/);
  assert.match(mobile, /\.stats\{grid-template-columns:repeat\(2,minmax\(0,1fr\)\)/);
  assert.match(mobile, /\.sched-items,\.cards,\.c-card,\.doc-card\{grid-template-columns:minmax\(0,1fr\);min-width:0/);
  assert.match(mobile, /\.d-grid\{grid-template-columns:minmax\(0,1fr\);min-width:0/);
  assert.match(mobile, /\.table-wrap\{max-width:100%;overflow-x:auto/);
  assert.doesNotMatch(mobile, /(?:html|body)\s*\{[^}]*overflow-x:\s*hidden/,
    'Do not suppress page overflow to mask broken layout');
});

test('Blitz mobile polish preserves accessible navigation, noindex and encrypted client-side unlock', () => {
  assert.match(html, /id="lock-btn"/);
  assert.match(html, /id="unlock-form"/);
  assert.match(html, /id="nav"/);
  assert.match(html, /id="example-banner"/);
  assert.match(html, /noindex, nofollow, noarchive/);
  assert.doesNotMatch(mobile, /data\.enc\.json|DASHBOARD_PASSPHRASE|firebase deploy/);
});
