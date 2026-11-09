import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normStatus, mdBlocks, parseCSV } from '../scripts/build.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const builder = path.join(root, 'scripts', 'build.mjs');
const secret = 'synthetic-local-test-passphrase-only';
const campaign = { name: 'Synthetic campaign', start: '2026-11-09', end: '2026-11-11', plan: {}, rules: ['Never auto-send'], accounts: ['Acme'] };
const header = 'key,account,contact,role,signal,connection_note,confirmation_status,due_date';
const row = 'ACME-JANE-20261109-CONNECT,Acme,Jane Example,CTO,"Email jane@example.com or call 312-555-0101",Synthetic connection note,Draft Ready,2026-11-09';

function fixture(t, opts = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'blitz-qa-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const src = path.join(dir, 'private');
  const out = path.join(dir, 'output');
  mkdirSync(src);
  writeFileSync(path.join(src, 'campaign.json'), JSON.stringify(opts.campaign ?? campaign));
  writeFileSync(path.join(src, 'activity_log.csv'), opts.csv ?? header + '\n' + row + '\n');
  writeFileSync(path.join(src, '2026-11-09_Acme_brief.md'), '# Daily brief\n## Needs from Steve\n- Confirm status\n');
  return { src, out, env: { ...process.env, BLITZ_DIR: src, BLITZ_OUTPUT_DIR: out, DASHBOARD_PASSPHRASE: secret } };
}

async function decrypt(blob, passphrase) {
  const base = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from(blob.salt, 'base64'), iterations: blob.iterations },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const bytes = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(blob.iv, 'base64') },
    key, Buffer.from(blob.ct, 'base64'));
  return JSON.parse(new TextDecoder().decode(bytes));
}

test('CSV parser handles quoted commas, escaped quotes, and empty-input errors', () => {
  assert.deepEqual(parseCSV('a,b\n"first, last","he said ""yes"""\n'), [{ a: 'first, last', b: 'he said "yes"' }]);
  assert.throws(() => parseCSV(''), /missing its header/);
});
test('status normalization preserves opt-out holds and does not claim sends', () => {
  assert.equal(normStatus('On Hold — opted out'), 'On Hold');
  assert.equal(normStatus('Sent Confirmed by seller'), 'Sent Confirmed');
  assert.equal(normStatus(''), 'Research Needed');
  assert.equal(normStatus('follow-up pending'), 'Next Action');
});
test('markdown parser keeps headings, bullet lists, and tables', () => {
  const blocks = mdBlocks('# Title\n## Actions\n- Research\n| Item | Status |\n| --- | --- |\n| Intro | Proposed |');
  assert.ok(blocks.some(x => x.type === 'heading' && x.text === 'Title'));
  assert.ok(blocks.some(x => x.type === 'bullet' && x.text === 'Research'));
  assert.ok(blocks.some(x => x.type === 'table' && x.rows.length === 2));
});
test('build encrypts synthetic campaign, scrubs contact details, and randomizes ciphertext', async t => {
  const f = fixture(t);
  execFileSync(process.execPath, [builder], { env: f.env, encoding: 'utf8' });
  const encryptedPath = path.join(f.out, 'data.enc.json');
  const one = JSON.parse(readFileSync(encryptedPath, 'utf8'));
  const text = readFileSync(encryptedPath, 'utf8');
  assert.equal(one.alg, 'AES-256-GCM');
  assert.equal(one.kdf, 'PBKDF2-SHA256');
  assert.equal(one.iterations, 600000);
  assert.equal(Buffer.from(one.salt, 'base64').length, 16);
  assert.equal(Buffer.from(one.iv, 'base64').length, 12);
  assert.doesNotMatch(text, /jane@example\.com|312-555-0101|Synthetic connection note/);
  const data = await decrypt(one, secret);
  assert.equal(data.contacts[0].account, 'Acme');
  assert.equal(data.contacts[0].status, 'Draft Ready');
  assert.equal(data.contacts[0].dueIso, '2026-11-09');
  assert.match(data.contacts[0].signal, /\[removed\]/);
  assert.equal(data.schedule.length, 3);
  assert.equal(data.needs.length, 1);
  await assert.rejects(() => decrypt(one, 'incorrect passphrase'));
  execFileSync(process.execPath, [builder], { env: f.env, encoding: 'utf8' });
  const two = JSON.parse(readFileSync(encryptedPath, 'utf8'));
  assert.notEqual(one.salt, two.salt);
  assert.notEqual(one.iv, two.iv);
  assert.notEqual(one.ct, two.ct);
});
test('dry run does not write a live dataset', t => {
  const f = fixture(t);
  const output = execFileSync(process.execPath, [builder, '--dry-run'], { env: { ...f.env, DASHBOARD_PASSPHRASE: '' }, encoding: 'utf8' });
  assert.match(output, /rows: 1/);
  assert.equal(existsSync(path.join(f.out, 'data.enc.json')), false);
});
test('invalid campaign dates fail closed without overwriting output', t => {
  const f = fixture(t, { campaign: { ...campaign, start: 'not-a-date' } });
  const result = spawnSync(process.execPath, [builder], { env: f.env, encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /valid start\/end dates/);
  assert.equal(existsSync(path.join(f.out, 'data.enc.json')), false);
});
test('duplicate contact keys fail closed', t => {
  const f = fixture(t, { csv: header + '\n' + row + '\n' + row + '\n' });
  const result = spawnSync(process.execPath, [builder], { env: f.env, encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Duplicate activity key/);
  assert.equal(existsSync(path.join(f.out, 'data.enc.json')), false);
});
test('real plaintext output is refused, while example dry-run needs no private data', t => {
  const f = fixture(t);
  const result = spawnSync(process.execPath, [builder, '--plain-check'], { env: f.env, encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /restricted to synthetic/);
  const example = spawnSync(process.execPath, [builder, '--example', '--dry-run'], { env: { ...f.env, BLITZ_DIR: '/nonexistent/source' }, encoding: 'utf8' });
  assert.equal(example.status, 0, example.stderr);
  assert.match(example.stdout, /rows: 4/);
});
test('published HTML keeps strict same-origin CSP and manual outreach', () => {
  const html = readFileSync(path.join(root, 'docs', 'index.html'), 'utf8');
  const js = readFileSync(path.join(root, 'docs', 'app.js'), 'utf8');
  assert.match(html, /default-src 'self'; script-src 'self'/);
  assert.match(html, /form-action 'none'/);
  assert.match(js, /data-copy-draft/);
  assert.match(js, /Steve sends manually/);
  assert.doesNotMatch(js, /linkedin\.com\/voyager\/api/);
});

test('two contacts sharing a first name keep different encrypted identities', async t => {
  const other = 'ACME-JANE-20261110-CONNECT,Acme,Jane Different,VP IT,Synthetic signal,Second draft,Draft Ready,2026-11-10';
  const f = fixture(t, { csv: header + '\n' + row + '\n' + other + '\n' });
  execFileSync(process.execPath, [builder], { env: f.env, encoding: 'utf8' });
  const blob = JSON.parse(readFileSync(path.join(f.out, 'data.enc.json'), 'utf8'));
  const data = await decrypt(blob, secret);
  assert.equal(data.contacts.length, 2);
  assert.notEqual(data.contacts[0].personKey, data.contacts[1].personKey);
  assert.equal(data.contacts[1].contact, 'Jane Different');
});
